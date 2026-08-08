package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/fatih/color"
	xterm "golang.org/x/term"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// DefaultPageSize is the share of the terminal the selection prompt occupies
// when --pagesize is not given.
const DefaultPageSize = 0.8

// DefaultCooldown is how long a release must have been out before it is recommended
// when --cooldown is not given. A week is long enough for a bad release to be noticed
// and short enough not to hold up ordinary maintenance.
const DefaultCooldown = "7d"

// DefaultChurn is the window over which repeated releasing is detected when --churn
// is not given.
//
// Four weeks is wide enough to tell a project that releases every few days from one
// that happened to publish twice, and narrow enough that a release from last quarter
// is not read as ongoing activity.
const DefaultChurn = "28d"

type AppEnv struct {
	Verbose bool
	// NonInteractive applies every available upgrade without asking, skipping the three
	// prompts: which modules, which version of a stepped module, which workspace members.
	//
	// It says nothing about the cooldown, which still decides what is available.
	NonInteractive bool
	// List writes a listing instead of applying upgrades. Nil means the caller said
	// nothing, which follows the output rather than meaning false, so read it through
	// listing() rather than directly.
	List     *bool
	PageSize float64
	Hook     string
	Ignore   []string
	Sort     string
	// Cooldown is how long a release must have been out before it is recommended,
	// and Churn the window over which repeated releasing is detected.
	//
	// The Set fields report whether the caller named the flag, which cannot be
	// inferred from the value: the flag carries the built-in default, so a caller
	// asking for exactly that is indistinguishable from one who said nothing --
	// and the two differ when a policy has an opinion.
	Cooldown    string
	CooldownSet bool
	Churn       string
	ChurnSet    bool
	// churn is the resolved window, once the flag and the policy have been
	// reconciled. Unlike the cooldown, which the module package needs for its
	// predicates, this one is only read while discovering versions.
	churn    time.Duration
	WorkSync bool
	// Color paints the output. On by default, since a person is the common reader;
	// --no-color turns it off.
	Color  bool
	Colors string
	// Labels is the --labels chain naming which rows a listing keeps, by the labels
	// they carry. It takes the same keys as Columns, so asking to see a property and
	// asking to select on it read alike.
	Labels string
	Format string
	// Columns is the -k chain naming which columns a listing shows.
	Columns string
	// Headers asks for a heading row. Nil means the caller said nothing, which
	// follows the output rather than meaning false, so read it through
	// showHeaders() rather than directly.
	Headers *bool
	// Tags names the build configurations to analyse, adjusting or replacing what
	// the project declares.
	Tags []string
	// policyTags is what the policy files asked for, used when the caller named
	// nothing.
	policyTags []string
	// Width is how many columns a listing may use. Zero means the terminal's own
	// width, which is the default; a negative value means unlimited, which also
	// renders versions in full; a positive value sets it explicitly.
	Width  int
	Policy []string
	// Timing asks for a report of what each phase of the run cost.
	Timing bool
	// Cache asks for a scan result to be reused. Nil means the caller said nothing,
	// which means "yes, unless timing" rather than false, so read it through
	// caching() rather than directly.
	Cache *bool
	// CacheFor is how long an answer about available upgrades is reused.
	CacheFor string
	// window is the resolved key fragment naming the current window, empty when nothing is
	// to be reused.
	window string
	// cache is where the caches live, empty when they could not be located.
	cache string
	// answers holds what has already been read from the toolchain this run, so a
	// question asked twice costs one command. A run is one shot, so nothing it reads
	// changes underneath it.
	//
	// A pointer so that AppEnv stays copyable, and so a copy shares the answers rather
	// than quietly starting empty. Nil until Run sets it, which recall treats as
	// "remember nothing" -- every gatherer still returns the right answer, it just
	// costs what it used to.
	answers *memo
	// reach is whether this run can ask a proxy what has been published, established once
	// at startup. An offline run can still report what it already knows, but must not
	// report silence as "up to date".
	reach reach
}

// upgradeCache returns where to keep answers about available upgrades and which window this run
// falls in, both empty when nothing is to be reused.
func (app *AppEnv) upgradeCache() (dir, window string) {
	if !app.caching() {
		return "", ""
	}
	return app.cache, app.window
}

// caching reports whether a scan result may be reused.
//
// On unless the caller declined, since reuse is what makes a second run quick. Off while
// timing, because a warm run skips the scan and timing one measures what reading a file costs
// rather than what the work costs -- which is not the question --timing is asked to answer.
//
// A caller who named --cache alongside --timing gets it: they may be measuring the cache
// itself, and an explicit flag is not something to override.
func (app *AppEnv) caching() bool {
	if app.Cache != nil {
		return *app.Cache
	}
	return !app.Timing
}

// view is how a listing is selected and rendered, resolved once at startup.
type view struct {
	sort    module.Sort
	filter  module.Filter
	format  string
	columns module.Columns
	// headers reports whether a heading row precedes a listing.
	headers bool
	// width is how wide a listing may be.
	width budget
	// rules decides what is permitted, nil when no policy was given.
	rules *policy.Policy
	// violations accumulates what the policy objected to across every
	// directory, so one report covers the whole run.
	violations *[]violation
}

// interactive reports whether the run is talking to a person.
//
// One fact, derived once, that the rest of the presentation follows from: whether a
// heading helps, and whether the rows are shaped for reading or for parsing.
// --non-interactive settles it, that flag meaning "do not ask" and there being nobody
// to ask when it is set. Otherwise the output decides, a terminal being where a person
// is.
func (app *AppEnv) interactive() bool {
	if app.NonInteractive {
		return false
	}
	return xterm.IsTerminal(int(os.Stdout.Fd()))
}

// listing reports whether the run writes a listing rather than applying upgrades.
//
// Unset follows the output, as the heading does: a run whose output is redirected is
// being read by something, and prompting a program that cannot answer would hang it.
// Saying either explicitly settles it, so a redirected run can still upgrade.
func (app *AppEnv) listing() bool {
	if app.List != nil {
		return *app.List
	}
	return !app.interactive()
}

// showHeaders reports whether a listing gets a heading row.
//
// A heading helps a person read six columns and hinders anything parsing them, so
// it follows the output by default: on at a terminal, off when redirected. Saying
// either explicitly settles it.
func (app *AppEnv) showHeaders() bool {
	if app.Headers != nil {
		return *app.Headers
	}
	return app.interactive()
}

// listWidth returns the columns a listing may use, and whether that is a limit
// at all.
//
// Zero, the default, means the terminal decides, which is what keeps a listing
// readable where it is being read. A negative value means unlimited: nothing is
// dropped or shortened, so a redirected listing can carry everything however wide
// it ends up. Anything else is used as it stands.
func (app *AppEnv) listWidth() (columns int, limited bool) {
	switch {
	case app.Width < 0:
		return 0, false
	case app.Width == 0:
		return terminalWidth(), true
	default:
		return app.Width, true
	}
}

// configurations returns the build configurations to analyse for the module in
// dir.
//
// What the project declares is the default: every distinct "//go:build" line it
// carries, plus the plain build. --tags adjusts or replaces that.
func (app *AppEnv) configurations(dir string) ([]tagFilter, error) {
	found, err := discoverFilters(dir)
	if err != nil {
		return nil, err
	}
	// A policy asking about advisories decides which configurations they are
	// looked for in, so naming the policy is enough. What the caller says on the
	// command line still wins: the policy states an intent, and an operator
	// narrowing a run is answering a question the file could not.
	specs := app.Tags
	if len(specs) == 0 {
		specs = app.policyTags
	}
	return ParseTags(specs, found)
}

// scope reports which dependencies the selectors ask for.
//
// Derived from what was asked for rather than carried by a flag of its own, because
// a selector naming a category nothing discovered is a question with no answer:
// --labels=indirect used to return an empty listing and exit 0, which reads as a
// project with no indirect requirements.
//
// --labels=all keeps every row, and every row there is differs from every row that
// happened to be discovered. --format=policy writes the module map of a policy file,
// which an allow-list can only mean anything against if it covers the whole build
// list. A label naming indirect requirements asks for what scopeDirect excludes.
//
// Only a key asking to keep rows widens the scope, which is where scope parts from
// the work a column demands. Demand is sign-agnostic because hiding the modules
// carrying an advisory still means finding out which ones do. Excluding is not:
// dropping a category is the same listing whether it was discovered and dropped or
// never discovered, so --labels=-all would otherwise resolve the whole build list to
// print nothing.
func (app *AppEnv) scope(filter module.Filter, format string) scope {
	switch {
	case filter.Keeps(module.FilterAll), format == module.FormatPolicy:
		return scopeAll
	case filter.Keeps(module.FilterIndirect):
		return scopeIndirect
	default:
		return scopeDirect
	}
}

// filterBase and columnBase are the defaults each selector starts from, which the
// value given adjusts.
//
// Neither widens for a flag any more. What a run gathers follows from the selectors
// themselves, so a base that grew an arm per flag would be a second place deciding
// what a listing shows -- and the arms were where a flag could widen one selector
// and not another.
func (app *AppEnv) filterBase() []string {
	return module.DefaultFilters()
}

func (app *AppEnv) columnBase() []string {
	// Which configurations reach a module, and so whether any build reaches it at
	// all. Empty when nothing was swept, which measure then drops.
	return append(module.DefaultColumns(), module.ColumnTags)
}

func (app *AppEnv) Run(ctx context.Context) error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	if !app.Color {
		color.NoColor = true
	}
	// Set before any phase runs, since a phase measures itself as it starts.
	// Answers are remembered for the life of the run, so a question asked by two
	// members or two configurations costs one command.
	app.answers = &memo{}
	SetTiming(app.Timing)
	startRun()
	defer ReportTiming()
	// Where the caches live and which window this run falls in. A cache that cannot be
	// located is not fatal: everything is read afresh, which is what happened before there
	// was one.
	if app.caching() {
		if at, err := cacheDir(); err != nil {
			log.WithError(err).Debug("Could not locate the cache, so reading everything afresh")
		} else {
			app.cache = at
			// Started here so the sweep proceeds while this run works, and not waited
			// on: nothing this run needs depends on it.
			pruneCache(ctx, app.cache, DefaultCacheLife)
		}
		for_, err := module.ParseDuration(app.CacheFor)
		if err != nil {
			return fmt.Errorf("cache-for: %w", err)
		}
		app.window = updateWindow(time.Now(), for_)
	}
	// Resolve the palette and the chain up front so an unusable value fails
	// before any network work has been done.
	if err := module.SetColors(app.Colors); err != nil {
		return err
	}
	// Each selector starts from a default that the value given adjusts.
	sorter, err := module.ParseSort(app.Sort, module.DefaultSorts())
	if err != nil {
		return err
	}
	filter, err := module.ParseFilter(app.Labels, app.filterBase())
	if err != nil {
		return err
	}
	format := app.Format
	if format == "" {
		format = module.DefaultFormat
	}
	if err := module.ValidFormat(format); err != nil {
		return err
	}
	// Settled here, once, so that nothing downstream asks again whether a person
	// is reading: auto becomes one of the two listings and the rest pass through.
	format = module.ResolveFormat(format, app.interactive())
	columns, err := module.ParseColumns(app.Columns, app.columnBase())
	if err != nil {
		return err
	}
	listCols, limited := app.listWidth()
	// A caller with room enough to see everything wants the versions in full
	// rather than abbreviated to a commit. A parseable listing has no width to
	// fit, and renders every value in full for the same reason.
	module.Wide = !limited || format == module.FormatTSV
	v := view{
		sort:       sorter,
		filter:     filter,
		format:     format,
		columns:    columns,
		headers:    app.showHeaders(),
		width:      budget{columns: listCols, limited: limited},
		violations: new([]violation),
	}
	if len(app.Policy) > 0 {
		rules, err := policy.Load(app.Policy)
		if err != nil {
			return err
		}
		v.rules = rules
		app.policyTags = rules.Tags()
		if len(app.policyTags) > 0 && len(app.Tags) == 0 {
			log.WithField("tags", strings.Join(app.policyTags, ", ")).
				Info("Policy asks for particular build configurations")
		}
		// A policy asking about advisories is showing them: it judges the run on what
		// the scan finds, and a reader handed a violation needs the finding beside the
		// row it is about. Unlike a label key, a policy has no mark in the listing to
		// speak through, so the column is how what it read becomes visible.
		//
		// Widened here rather than in columnBase because a policy is read after the
		// columns are resolved, which is what made the flag this replaces set too late
		// to be seen. An explicit --columns still wins: With adds nothing to a chain
		// that named its columns outright, nor one that excluded this column.
		if rules.ScansVulnerabilities() {
			v.columns = v.columns.With(module.ColumnVuln)
		}
	}
	// Resolved after the policy is read, since a policy may set the periods and the
	// caller overrides it -- but still before any network work, so an unusable value
	// or a contradictory pair fails immediately.
	var policyCooldown, policyChurn *time.Duration
	if v.rules != nil {
		if d, ok := v.rules.Cooldown(); ok {
			policyCooldown = &d
		}
		if d, ok := v.rules.Churn(); ok {
			policyChurn = &d
		}
	}
	cooldown, churn, err := app.periods(policyCooldown, policyChurn)
	if err != nil {
		return err
	}
	module.SetCooldown(cooldown)
	app.churn = churn
	// Said against the scope rather than against a flag, since several selectors reach
	// the whole build list and every one of them can offer a module go.mod does not
	// record.
	if app.scope(v.filter, v.format) == scopeAll {
		log.Info("Upgrading a module outside go.mod adds an `// indirect` entry; recommend running `go mod tidy` afterwards")
	}
	// Both in one invocation, since each costs a process start to answer a question about
	// this run's configuration. GOPROXY decides whether anything published can be
	// discovered at all, which nothing downstream can infer for itself.
	gw, err := exec.CommandContext(ctx, "go", "env", "GOWORK", "GOPROXY").Output()
	if err != nil {
		return err
	}
	gowork, goproxy := splitEnvLines(string(gw))
	workspace := gowork != "" && gowork != "off"

	app.reach = reachFrom(goproxy)
	if app.reach.offline() {
		// Said once, up front, rather than against each module: it is a fact about the
		// run. What it means for any given module is reported in the listing.
		log.WithFields(log.Fields{"proxy": goproxy}).
			Warn("No proxy to ask, so upgrades cannot be discovered; reporting what is already known")
	}

	var dirs []string
	if workspace {
		log.WithField("gowork", gowork).Info("Workspace mode")
		// Which members require a module is what makes a merged listing readable: one
		// row stands for several members, and without this the row cannot say which.
		// A single module needs no such column -- there is only one requirer, and
		// naming it in every row says nothing -- so this follows the workspace rather
		// than being a default the simple case has to turn off.
		//
		// Added here because it is decided by what was discovered, not by what was
		// asked for, and nothing between here and the listing has read the columns yet.
		// An explicit --columns still wins: this widens the set, and ParseColumns has
		// already applied whatever narrowing was named.
		v.columns = v.columns.With(module.ColumnRequiredBy)
		// Each member is reported against its own go.mod, which is what an upgrade edits.
		// That differs from the versions the workspace builds against whenever the members
		// disagree, so say which the listing means.
		log.Info("Upgrades are relative to each member's own go.mod, not the versions the workspace resolves")
		dirs, err = workspaceDirs(gowork)
		if err != nil {
			return err
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		dirs = append(dirs, cwd)
	}

	// A module that cannot be read should not hide the updates available in
	// the rest of the workspace, so failures are collected and reported once
	// every module has been given a chance.
	var errs []error
	updated := 0
	if workspace {
		// The members of a workspace share most of their dependencies, so
		// offering each member separately would ask about the same upgrade
		// repeatedly. Gather them into one list instead.
		//
		// A workspace is one thing to work on, so it gets one listing whatever
		// was asked for. Gating this on a flag made the shape of the output a
		// second thing that flag decided: --labels=all printed five listings
		// repeating the dependencies the members share, where the flag it
		// replaces printed one.
		n, err := app.runWorkspace(ctx, dirs, v)
		if err != nil {
			errs = append(errs, err)
		}
		updated += n
	} else {
		for _, dir := range dirs {
			n, err := app.runDir(ctx, dir, v)
			if err != nil {
				log.WithFields(log.Fields{
					"dir":   dir,
					"error": err,
				}).Error("Skipping module")
				errs = append(errs, fmt.Errorf("%q: %w", dir, err))
				continue
			}
			updated += n
		}
	}

	if workspace && app.WorkSync && updated > 0 {
		if err := workSync(ctx, filepath.Dir(gowork)); err != nil {
			errs = append(errs, err)
		}
	}
	// The policy is reported once for the whole run, so a workspace shows
	// everything to be done rather than one member at a time.
	if v.rules != nil {
		// report prints them; the error carries them, so the status is worked out
		// where it is needed rather than fixed here.
		if failed := report(*v.violations); failed {
			errs = append(errs, &PolicyError{Violations: *v.violations})
		}
	}
	return errors.Join(errs...)
}

// PolicyError reports what a policy objected to.
//
// It carries the violations rather than an exit code. What to do about them depends on
// the flags a run was given, which the error cannot see -- so deciding here would fix a
// choice that belongs to the caller, and any caller wanting to count the violations or
// render them itself would be stuck with it.
type PolicyError struct {
	Violations []violation
}

// Error lists every violation rather than counting them.
//
// A message saying "2 violations" sends a reader back to the report to learn which, and
// anything capturing the error rather than the terminal -- a log aggregator, a test, a
// wrapping tool -- would have lost them entirely.
func (e *PolicyError) Error() string {
	if len(e.Violations) == 0 {
		return "policy violations found"
	}
	lines := make([]string, 0, len(e.Violations))
	for _, v := range e.Violations {
		lines = append(lines, v.String())
	}
	return "policy violations found: " + strings.Join(lines, "; ")
}

// ExitStatus reports the status this run should leave with.
//
// A method rather than a function because the answer depends on how the run was invoked,
// not only on what went wrong: the same violations mean different things to a listing and
// to an upgrade. The highest status any failing action asked for wins, so a warning
// alongside a failure still fails and a policy naming 42 gets 42.
func (app *AppEnv) ExitStatus(err error) int {
	if err == nil {
		return 0
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		status := 0
		for _, v := range pe.Violations {
			if got := v.Action.Status(); got > status {
				status = got
			}
		}
		if status > 0 {
			return status
		}
	}
	// Something went wrong and no policy chose a code for it.
	return 1
}

// runWorkspace offers the updates available across every module of a
// workspace as one list, and reports how many modules were updated.
//
// The members of a workspace share most of their dependencies, so each upgrade
// is offered once and applied to whichever members require it. RequiredBy
// names those members, which is what makes the choice meaningful: whether a
// module is required directly is a property of each member, not of the
// workspace.
func (app *AppEnv) runWorkspace(ctx context.Context, dirs []string, v view) (int, error) {
	// Which members require a given module, keyed by module path.
	members := map[string][]string{}
	// Which members require each version of a module, keyed by module path and then
	// by the version required. One row stands for every member, so the versions they
	// disagree about have to be kept to report any of them truthfully.
	required := map[string]map[string][]string{}
	// One representative entry per module, holding the versions to show.
	byPath := map[string]module.Module{}
	// Advisories seen for a module, in any member that requires it.
	found := vulnerabilities{}
	// The oldest toolchain any member declares, which is the one a standard
	// library advisory is worst in and so the one to report.
	var oldest *semver.Version
	// Which modules any member's build reaches, so an upgrade is only suggested
	// for something the code imports.
	reached := map[string]struct{}{}
	// Which configurations reach each module, so a listing can say a module is
	// only in the build under some of them.
	spread := newTagSpread()
	// Each member's own configurations, since members declare their own build tags.
	// Analysing every member under one member's tags would report a build no member has.
	var builds []buildAt
	var errs []error

	// Read every member at once. Each resolves its own build list independently, which Go
	// redoes per invocation, so reading them one after another was almost the whole cost of
	// discovery. What follows merges them into shared maps and stays serial, in the order the
	// members were given, so a run reports the same thing however the reads landed.
	type discovery struct {
		modules []module.Module
		mod     declared
		cached  bool
		age     cacheAge
	}
	read := discoverAcross(dirs, func(dir string) (discovery, error) {
		modules, mod, cached, age, err := app.discoverModules(ctx, dir, app.Ignore, app.scope(v.filter, v.format), app.cache, app.window)
		return discovery{modules: modules, mod: mod, cached: cached, age: age}, err
	})

	for at, dir := range dirs {
		analysed(dir, read[at].value.cached, read[at].value.age)
		discovered, mod, err := read[at].value.modules, read[at].value.mod, read[at].err
		if err != nil {
			log.WithFields(log.Fields{
				"dir":   dir,
				"error": err,
			}).Error("Skipping module")
			errs = append(errs, fmt.Errorf("%q: %w", dir, err))
			continue
		}
		if declaredGo := mod.stdlibVersion(); declaredGo != "" {
			if v, err := semver.NewVersion(declaredGo); err == nil {
				if oldest == nil || v.LessThan(oldest) {
					oldest = v
				}
			}
		}
		// Each member is swept across its own configurations, since members declare
		// their own build tags. What the sweep reaches is what makes an upgrade
		// worth suggesting rather than merely effective, so it is gathered whether
		// or not advisories are being looked for.
		filters, err := app.configurations(dir)
		if err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
		logConfigurations(dir, filters)
		deps, err := sweep(ctx, "Inspecting "+filepath.Base(dir), filters,
			func(ctx context.Context, f tagFilter) (dependents, error) {
				return app.importGraph(ctx, dir, f)
			})
		if err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
		merged, where := mergeDependents(filters, deps)
		for mod := range merged {
			reached[mod] = struct{}{}
		}
		spread.add(filters, where)

		// Collected rather than acted on here: what the configurations are wanted for
		// is decided by the demand, once every member has been read.
		builds = append(builds, buildAt{dir: dir, filters: filters})
		for _, m := range discovered {
			members[m.Name] = append(members[m.Name], dir)
			// What this member asked for, before the merge below settles on one of
			// them. Recorded per member so a listing can report the version each
			// requires rather than only the oldest.
			if required[m.Name] == nil {
				required[m.Name] = map[string][]string{}
			}
			version := m.From.Original()
			required[m.Name][version] = append(required[m.Name][version], dir)
			// Members can require different versions of the same module. Keep
			// the oldest, since that is the one most in need of the upgrade.
			if prev, ok := byPath[m.Name]; !ok || m.From.LessThan(prev.From) {
				byPath[m.Name] = m
			}
		}
	}

	modules := make([]module.Module, 0, len(byPath))
	for path, m := range byPath {
		// Sort only what is displayed; the members map keeps its own order so
		// that a choice can be mapped back to a directory.
		names := relativeTo(members[path], dirs)
		slices.Sort(names)
		m.RequiredBy = names
		// Carried only where the members disagree, so that everything downstream can
		// treat its presence as the disagreement itself rather than comparing versions
		// again. The directories are named as the listing names them, since this is
		// what a row reports.
		if len(required[path]) > 1 {
			m.Required = map[string][]string{}
			for version, at := range required[path] {
				named := relativeTo(at, dirs)
				slices.Sort(named)
				m.Required[version] = named
			}
		}
		modules = append(modules, m)
	}
	// Which configurations reach a module, from the sweep each member already ran.
	// Free for the same reason as in runDir.
	spread.annotate(modules)
	// What the selectors asked about, answered. The oldest version any member declares
	// is what a standard library advisory is reported against, a workspace being as far
	// behind as its furthest-behind member.
	version := ""
	if oldest != nil {
		version = oldest.String()
	}
	where := site{
		at:      builds,
		into:    &modules,
		found:   &found,
		reached: reached,
		stdlib:  version,
	}
	for _, column := range app.demands(v).Ordered() {
		if err := app.fill(ctx, column, where); err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
	}
	// An advisory that was found is shown, so the identifiers the scan paid for reach
	// the reader rather than only the letter standing for them.
	//
	// Widened after the fill loop, that being where the answer exists: found is empty
	// until the scan writes through it. Reassigning the local is enough because every
	// render call is made downward from this frame, after this point.
	v.columns = showingAdvisories(v.columns, found)
	// After the advisories, since a module whose advisories the code reaches is
	// exempt from the cooldown. A release history is a property of the module rather
	// than of any one member, so any member's directory can read it -- as the
	// resolvers above already do.
	var candidates map[string][]release
	if len(dirs) > 0 {
		// Before the histories are read, since which of them are worth reading is
		// decided by asking each module whether it is still cooling.
		if v.rules != nil {
			annotateCooldowns(v.rules, modules)
		}
		var err error
		if candidates, err = app.settle(ctx, dirs[0], modules); err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
	}
	slices.SortStableFunc(modules, v.sort.Compare)
	if v.rules != nil {
		// Annotate before checking, so the listing and the report describe the
		// same modules.
		annotateArchived(v.rules, modules)
		*v.violations = append(*v.violations, enforce(v.rules, modules)...)
		// The oldest version any member declares, since that is the one outside the
		// window if any is: a workspace is as far behind as its furthest-behind member.
		if oldest != nil {
			*v.violations = append(*v.violations, app.checkGoVersion(ctx, v.rules, oldest.String())...)
		}
	}

	if len(modules) == 0 {
		log.WithFields(log.Fields{"members": len(dirs), "why": "no module was discovered to compare"}).
			Info("All modules are up to date")
		// The listing is still written, so a reader parsing one is handed the empty
		// listing their format defines rather than no output at all.
		if app.listing() {
			if err := present(modules, v); err != nil {
				errs = append(errs, err)
			}
		}
		return 0, errors.Join(errs...)
	}
	if app.listing() {
		if err := present(modules, v); err != nil {
			errs = append(errs, err)
		}
		return 0, errors.Join(errs...)
	}
	considered := len(modules)
	held := countCooling(modules)
	modules = upgradable(modules, v.filter.Wants(module.FilterCooldown))
	if len(modules) == 0 {
		// Discovery keeps the modules already at their newest version so that a
		// policy can judge them, so reaching here is the ordinary "nothing to
		// do" rather than a module with no requirements.
		log.WithFields(log.Fields{
			"members":    len(dirs),
			"considered": considered,
			"cooling":    held,
			"why":        "no module has a newer release to take",
		}).Info("All modules are up to date")
		return 0, errors.Join(errs...)
	}
	if !app.NonInteractive {
		modules = choose(modules, app.PageSize, v.columns, v.width)
		// Which version to take is a property of the module, so it is asked once here
		// rather than per member below.
		if err := askVersions(modules, candidates, app.PageSize, v.rules); err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
	} else {
		log.WithField("modules", len(modules)).
			Debug("Applying every available upgrade without asking")
	}

	// Withheld before any member is touched, since an upgrade forbidden in one member
	// is forbidden in all of them: the policy names modules, not directories. Any
	// member's directory can read what a target requires.
	if len(dirs) > 0 {
		kept, refused := app.permitted(ctx, dirs[0], modules, v.rules, found)
		// Collected, not returned: the upgrades not refused still apply, and the
		// report says which were withheld once the run finishes.
		*v.violations = append(*v.violations, refused...)
		modules = kept
	}

	updated := 0
	for _, m := range modules {
		dirs := members[m.Name]
		// A module required by one member has nothing to choose between, and a
		// non-interactive run takes everything by definition.
		if len(dirs) > 1 && !app.NonInteractive {
			chosen, err := chooseMembers(m, dirs, relativeTo(dirs, dirs), app.PageSize)
			if err != nil {
				return updated, errors.Join(append(errs, err)...)
			}
			dirs = chosen
		}
		for _, dir := range dirs {
			update(ctx, dir, []module.Module{m}, app.Hook)
			updated++
		}
	}
	return updated, errors.Join(errs...)
}

// chooseMembers asks which of the members requiring a module should have it
// upgraded. Whether the requirement is direct differs between members, so this
// cannot be decided once for the workspace.
func chooseMembers(mod module.Module, dirs, names []string, pageSize float64) ([]string, error) {
	options := slices.Clone(names)
	// Everything is selected to begin with, since upgrading a module
	// everywhere it is required is the usual intent.
	defaults := make([]int, len(options))
	for i := range options {
		defaults[i] = i
	}

	message := fmt.Sprintf("Update %s to %s in which modules?", mod.Name, mod.To.Original())
	choice, answered, err := askMulti(message, "", options, defaults, pageRows(pageSize))
	if err != nil {
		return nil, err
	}
	if !answered {
		quit()
	}

	// The prompt reports positions in the option list, which was built from
	// names in the same order as dirs.
	out := make([]string, 0, len(choice))
	for _, i := range choice {
		out = append(out, dirs[i])
	}
	return out, nil
}

// relativeTo shortens member directories to something readable, by naming them
// relative to the directory they share.
//
// The result is ordered to match dirs, so a choice made against these names can
// be mapped back to the directory it refers to.
func relativeTo(dirs []string, all []string) []string {
	base := commonDir(all)
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		name := dir
		if base != "" {
			if rel, err := filepath.Rel(base, dir); err == nil {
				name = rel
			}
		}
		if name == "." {
			// filepath.Rel writes a directory equal to the base as ".", which
			// names nothing a reader recognises in a list of workspace members.
			// Its own last segment is what they know it by. Note this is the
			// directory's base, not the common prefix's: the two differ whenever
			// the members share no parent above the root.
			name = filepath.Base(dir)
		}
		out = append(out, name)
	}
	return out
}

// commonDir returns the longest path prefix shared by every directory.
func commonDir(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	base := dirs[0]
	for _, dir := range dirs[1:] {
		for base != "" && base != string(filepath.Separator) {
			if dir == base || strings.HasPrefix(dir, base+string(filepath.Separator)) {
				break
			}
			base = filepath.Dir(base)
		}
	}
	return base
}

// runDir offers the updates available in one module directory and reports how
// many modules were updated.
func (app *AppEnv) runDir(ctx context.Context, dir string, v view) (int, error) {
	modules, mod, cached, age, err := app.discoverModules(ctx, dir, app.Ignore, app.scope(v.filter, v.format), app.cache, app.window)
	if err != nil {
		return 0, err
	}
	// Said after discovery rather than before it, so the line can report whether the
	// versions came from a recent answer and how old that answer is.
	analysed(dir, cached, age)

	// Which build configurations to analyse. A tag decides which files compile,
	// so analysing only what a plain build sees under-reports whatever the tests
	// or a platform-specific file pull in.
	filters, err := app.configurations(dir)
	if err != nil {
		return 0, err
	}
	logConfigurations(dir, filters)

	// Which modules contribute a package to the build, under any configuration.
	// An upgrade is only worth suggesting for a module the code actually reaches,
	// so this is gathered whether or not the dependents are being displayed.
	var reached map[string]struct{}
	{
		found, err := sweep(ctx, "Inspecting dependencies", filters,
			func(ctx context.Context, f tagFilter) (dependents, error) {
				return app.importGraph(ctx, dir, f)
			})
		if err != nil {
			return 0, err
		}
		deps, where := mergeDependents(filters, found)
		reached = make(map[string]struct{}, len(deps))
		for mod := range deps {
			reached[mod] = struct{}{}
		}
		// Attached unconditionally: the sweep above ran to compute reached, so both
		// annotations are map lookups over data already paid for. Whether a listing
		// shows them is decided by the columns asked for, and measure drops a column
		// nothing fills -- so gating the assignment only withheld what was gathered.
		for i := range modules {
			modules[i].RequiredBy = deps[modules[i].Name]
		}
		annotateTags(modules, where, len(filters))
	}
	// Gathered here so the CVE guard can see them below, outside the filling's own
	// block: an upgrade is refused for where it lands, which is decided after this.
	vulns := vulnerabilities{}
	// What the selectors asked about, answered. A column displaying a property and a
	// label key selecting on it are two reasons to want one answer, so the work follows
	// from the demand rather than from a flag that happened to gate it.
	where := site{
		at:      []buildAt{{dir: dir, filters: filters}},
		into:    &modules,
		found:   &vulns,
		reached: reached,
		stdlib:  mod.stdlibVersion(),
	}
	for _, column := range app.demands(v).Ordered() {
		if err := app.fill(ctx, column, where); err != nil {
			return 0, err
		}
	}
	// Shown once found, for the reason runWorkspace widens it.
	v.columns = showingAdvisories(v.columns, vulns)
	// After the advisories are attached, since a module whose advisories the code
	// reaches is exempt from the cooldown and so has nothing to step back from.
	// Before the sort, so a module that stepped is ordered by what is now available.
	//
	// The per-module periods come first: which histories are worth reading is decided
	// by asking each module whether it is still cooling, so a module a policy exempted
	// has to know that before it is asked.
	if v.rules != nil {
		annotateCooldowns(v.rules, modules)
	}
	candidates, err := app.settle(ctx, dir, modules)
	if err != nil {
		return 0, err
	}
	supported, err := toolsSupported(ctx)
	if err != nil {
		return 0, err
	}
	log.WithFields(log.Fields{
		"supported": supported,
	}).Debug("Tool support")
	if supported {
		toolModules, err := discoverTools(ctx, dir, app.Ignore)
		if err != nil {
			return 0, err
		}
		modules = append(modules, toolModules...)
	}
	// Sort once the tool modules have been merged in, so the whole list
	// shares one order rather than tools trailing behind.
	slices.SortStableFunc(modules, v.sort.Compare)
	if v.rules != nil {
		// Annotate before checking, so the listing and the report describe the
		// same modules.
		annotateArchived(v.rules, modules)
		*v.violations = append(*v.violations, enforce(v.rules, modules)...)
		// The Go version the project declares, which is about the project rather than
		// about any module it requires -- so it is checked here rather than inside
		// enforce, which walks the modules.
		*v.violations = append(*v.violations, app.checkGoVersion(ctx, v.rules, mod.stdlibVersion())...)
	}
	if len(modules) == 0 {
		log.WithFields(log.Fields{"dir": dir, "why": "no module was discovered to compare"}).
			Info("All modules are up to date")
		// The listing is still written, so a reader parsing one is handed the empty
		// listing their format defines rather than no output at all.
		if app.listing() {
			return 0, present(modules, v)
		}
		return 0, nil
	}
	if app.listing() {
		return 0, present(modules, v)
	}
	considered := len(modules)
	held := countCooling(modules)
	modules = upgradable(modules, v.filter.Wants(module.FilterCooldown))
	if len(modules) == 0 {
		// Discovery keeps the modules already at their newest version so that a
		// policy can judge them, so reaching here is the ordinary "nothing to
		// do" rather than a module with no requirements.
		log.WithFields(log.Fields{
			"dir":        dir,
			"considered": considered,
			"cooling":    held,
			"why":        "no module has a newer release to take",
		}).Info("All modules are up to date")
		return 0, nil
	}
	if !app.NonInteractive {
		modules = choose(modules, app.PageSize, v.columns, v.width)
		// A module that stepped back passed over a newer release. The reader chose the
		// module; which of its versions to take is theirs to decide too.
		if err := askVersions(modules, candidates, app.PageSize, v.rules); err != nil {
			return 0, err
		}
	} else {
		log.WithFields(log.Fields{"dir": dir, "modules": len(modules)}).
			Debug("Applying every available upgrade without asking")
	}
	// Last, once the versions are settled: an upgrade that would land a version the
	// policy forbids is withheld rather than applied and reported afterwards. Applied
	// and reported is what let a clean run install a version the next run failed on.
	//
	// After askVersions, since a reader may have changed which version is on offer, and
	// it is the outcome that is judged. Also under --non-interactive, where nothing was
	// chosen and so nothing is exempt.
	// The upgrades a refusal did not touch are still worth applying, so the refusals
	// join the violation list and are reported with everything else the policy decided
	// rather than ending the run here.
	modules, refused := app.permitted(ctx, dir, modules, v.rules, vulns)
	*v.violations = append(*v.violations, refused...)
	if len(modules) == 0 {
		return 0, nil
	}
	update(ctx, dir, modules, app.Hook)
	return len(modules), nil
}

// workSync runs go work sync, which brings every module in the workspace onto
// the versions the workspace as a whole selects.
func workSync(ctx context.Context, dir string) error {
	log.WithField("dir", dir).Info("Synchronizing workspace")
	cmd := exec.CommandContext(ctx, "go", "work", "sync")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"out":   string(out),
		}).Error("Error while synchronizing workspace")
		return fmt.Errorf("error running go work sync: %w", err)
	}
	return nil
}

// permittedEnv names the environment variables a "go" invocation inherits.
//
// An allow-list, because a variable that reaches the toolchain can change its answer:
// GOPROXY=off turns an available upgrade into "up to date", GOFLAGS can carry -mod or -tags,
// GOOS decides which files compile and so what a scan finds reachable. Every cache here keys
// on what decides its answer, so such a variable must be either excluded or keyed -- and the
// whole environment cannot be keyed, holding as it does values that differ between two runs
// that should share an answer.
//
// keyedEnv keys exactly what this admits, so adding a variable here does both at once and
// neither can drift from the other.
//
// The non-Go entries are here to reach a module at all rather than to choose a version: PATH
// finds the toolchain and git, HOME locates .netrc and .gitconfig, SSH_AUTH_SOCK
// authenticates a private module, and the proxy variables are how a restricted site reaches a
// proxy.
var permittedEnv = map[string]struct{}{
	// Where the toolchain and its helpers are found.
	"PATH": {}, "HOME": {}, "TMPDIR": {},
	// How a private module is fetched and authenticated.
	"SSH_AUTH_SOCK": {}, "NETRC": {},
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {},
	"http_proxy": {}, "https_proxy": {}, "no_proxy": {},
	// Where modules come from and which are private.
	"GOPROXY": {}, "GONOPROXY": {}, "GOPRIVATE": {}, "GOSUMDB": {}, "GONOSUMDB": {},
	"GONOSUMCHECK": {}, "GOINSECURE": {}, "GOAUTH": {}, "GOVCS": {},
	// Where the caches and module tree live.
	"GOPATH": {}, "GOMODCACHE": {}, "GOCACHE": {}, "GOTMPDIR": {},
	// Which toolchain runs and what it targets.
	"GOROOT": {}, "GOTOOLCHAIN": {}, "GOOS": {}, "GOARCH": {}, "GOARM64": {},
	"GOFLAGS": {}, "GO111MODULE": {}, "GODEBUG": {}, "GOEXPERIMENT": {}, "GOFIPS140": {},
	// Whether cgo is available, which decides which files build.
	"CGO_ENABLED": {},
	// Which work file is in effect, when the caller named one.
	"GOWORK": {},
}

// goEnv returns the environment a "go" invocation runs with, given the environment cmd
// would otherwise have used.
//
// Everything outside permittedEnv is dropped. A permitted variable is passed through as it
// stands, including when it is set to nothing: "GOFLAGS=" is a value the toolchain reads
// differently from GOFLAGS being absent, so dropping it would quietly change the run.
//
// PWD is carried through as cmd.Environ() set it, so the child is told where it actually runs
// rather than where this process does.
func goEnv(env []string) []string {
	out := make([]string, 0, len(permittedEnv)+1)
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// cmd.Environ() derives PWD from cmd.Dir, so it names the directory the command
		// runs in rather than this process's.
		if k == "PWD" {
			out = append(out, kv)
			continue
		}
		if _, permitted := permittedEnv[k]; permitted {
			out = append(out, kv)
		}
	}
	return out
}

// keyedEnv returns every permitted variable as a sorted key fragment.
//
// Exactly what goEnv admits, so a variable cannot steer the toolchain without reaching the
// key. Sorted, since a map gives no ordering and a key that varied with it would never hit.
//
// Unset, empty and set are three fragments rather than two, because the toolchain reads them
// as three states: GOPROXY= is an empty proxy list, not the default. Omitting the unset ones
// would let a run that cleared a variable be handed the answer gathered before it was
// cleared.
//
// GOWORK contributes the work file's contents as well as its path, since editing a use
// directive changes which modules resolve without the path changing. Only when it is in
// effect: every invocation otherwise runs with GOWORK=off, where the file decides nothing.
func keyedEnv() []string {
	return keyedEnvExcept("")
}

// keyedEnvExcept is keyedEnv with one variable left out, for a key that must survive that
// variable changing.
//
// The offline fallback is the reason it exists. GOPROXY is keyed because it decides where an
// answer came from -- switching it off turns an available upgrade into "up to date", so an
// ordinary run must not be handed an answer gathered under different rules. But the fallback is
// read by a run whose GOPROXY differs from the run that wrote it, by definition: that difference
// is what makes it offline. Keyed on GOPROXY, the entry could never be found by the only caller
// it exists for.
//
// Safe here because nothing is being reused across configurations that disagree. What the
// fallback offers is the last answer about these requirements, presented as history with its age
// rather than as this run's findings.
func keyedEnvExcept(skip string) []string {
	out := make([]string, 0, len(permittedEnv))
	for k := range permittedEnv {
		if k == skip {
			continue
		}
		v, ok := os.LookupEnv(k)
		if !ok {
			// Named rather than omitted, so becoming unset changes the key.
			out = append(out, k+"\x00unset")
			continue
		}
		entry := k + "\x00set=" + v
		if k == "GOWORK" && v != "" && v != "off" {
			entry += "\x00" + workSum(v)
		}
		out = append(out, entry)
	}
	slices.Sort(out)
	return out
}

// workSum digests the work file at path, for a cache key.
//
// The length is hashed with the contents so the digest commits to both. A digest over bare
// bytes lets two different inputs agree once they are concatenated with anything else; the
// length pins where the payload ends.
//
// A file that cannot be read digests to its error rather than failing the run: an unreadable
// work file is one the toolchain will not read either, and the key only has to change when
// the answer might.
func workSum(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	sum := sha256.New()
	fmt.Fprintf(sum, "%d\n", len(body))
	sum.Write(body)
	return hex.EncodeToString(sum.Sum(nil))
}

// scanEnv returns the environment a vulnerability scan runs with.
//
// The same permitted set and the same workspace default as noWorkspace, built from the
// process environment because scan.Cmd carries no directory to derive a PWD from.
func scanEnv() []string {
	env := goEnv(os.Environ())
	if os.Getenv("GOWORK") != "" {
		return env
	}
	return append(env, "GOWORK=off")
}

// noWorkspace has cmd resolve the module in its own directory rather than the workspace
// containing it, and confines it to the permitted environment. Call it after setting
// cmd.Dir, whose value it reads.
//
// "go env GOWORK" walks up from the working directory, so a subdirectory of a workspace picks
// the work file up with no opt-in, and then the greatest version any member requires wins. A
// member requiring x/text v0.3.0 beside one pinning v0.40.0 would resolve to v0.40.0 and be
// reported as needing nothing while its own go.mod stood 37 minor versions behind. See
// https://github.com/oligot/go-mod-upgrade/issues/35
//
// An explicit GOWORK is left alone: naming a work file is more specific than this default,
// and overruling it would leave no way to ask. Empty counts as unset, as the toolchain reads
// it.
func noWorkspace(cmd *exec.Cmd) {
	env := goEnv(cmd.Environ())
	if os.Getenv("GOWORK") != "" {
		cmd.Env = env
		return
	}
	cmd.Env = append(env, "GOWORK=off")
}

func discoverTools(ctx context.Context, dir string, ignoreNames []string) ([]module.Module, error) {
	stop, err := progress("Discovering tool modules...")
	if err != nil {
		return nil, err
	}
	defer stop()

	toolsArgs := []string{
		"list",
		"-f",
		"{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}",
		"tool",
	}
	cmd := exec.CommandContext(ctx, "go", toolsArgs...)
	cmd.Dir = dir
	noWorkspace(cmd)
	toolsOutput, err := cmd.Output()

	if err != nil {
		if strings.Contains(err.Error(), "matched no packages") {
			return []module.Module{}, nil
		}
		log.WithFields(log.Fields{
			"error": err,
			"args":  cmd.Args,
		}).Error("error listing tools")
		return nil, fmt.Errorf("error listing tools: %w", err)
	}

	var modules []module.Module
	tools := strings.Split(strings.TrimSpace(string(toolsOutput)), "\n")
	for _, tool := range tools {
		if tool == "" {
			continue
		}

		parts := strings.Fields(tool)
		if len(parts) == 1 {
			continue // local tool
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tool format: %s", tool)
		}
		toolPath, currentVersion := parts[0], parts[1]

		// Check for updates. Query as path@version so the lookup does not
		// depend on the main module's build list or go.sum.
		updateArgs := []string{
			"list",
			"-m",
			"-f",
			"{{if .Update}}{{.Update.Version}}{{end}}",
			"-u",
			"-e",
			toolPath + "@" + currentVersion,
		}
		updateCmd := exec.CommandContext(ctx, "go", updateArgs...)
		updateCmd.Dir = dir
		noWorkspace(updateCmd)
		if updateOutput, err := updateCmd.Output(); err == nil {
			// A tool already at its newest version reports nothing here. It is
			// kept, standing at the version it already holds, so that a policy
			// sees it as it sees any other module.
			newVersion := strings.TrimSpace(string(updateOutput))
			if newVersion == "" {
				newVersion = currentVersion
			}
			fromVersion, err := semver.NewVersion(currentVersion)
			if err != nil {
				return nil, fmt.Errorf("invalid tool version: %s -> %s: %w", toolPath, currentVersion, err)
			}
			toVersion, err := semver.NewVersion(newVersion)
			if err != nil {
				return nil, fmt.Errorf("invalid tool update version: %s -> %s: %w", toolPath, newVersion, err)
			}
			log.WithFields(log.Fields{
				"tool": toolPath,
				"from": currentVersion,
				"to":   newVersion,
			}).Debug("Found tool module")
			modules = append(modules, module.Module{
				Name:    toolPath,
				From:    fromVersion,
				To:      toVersion,
				Ignored: shouldIgnore(toolPath, currentVersion, newVersion, ignoreNames),
			})
		}
	}

	// Clear the spinner before the caller starts printing, so its trailing
	// blanks do not end up on the first line of the listing.
	stop()
	return modules, nil
}

func toolsSupported(ctx context.Context) (bool, error) {
	gv, err := exec.CommandContext(ctx, "go", "version").Output()
	if err != nil {
		return false, err
	}

	version := strings.TrimSpace(string(gv))
	re := regexp.MustCompile(`go version go([\d\.]+)(rc.+)?`)
	matched := re.FindStringSubmatch(version)
	if len(matched) < 2 {
		return false, fmt.Errorf("couldn't parse go version %s", version)
	}

	goversion, err := semver.NewVersion(matched[1])
	if err != nil {
		return false, err
	}
	log.WithFields(log.Fields{
		"major": goversion.Major(),
		"minor": goversion.Minor(),
	}).Debug("Go version")
	if goversion.Major() >= 1 && goversion.Minor() >= 24 {
		return true, nil
	}
	return false, nil
}

func shouldIgnore(name, from, to string, ignoreNames []string) bool {
	for _, ig := range ignoreNames {
		if strings.Contains(name, ig) {
			c := color.New(color.FgYellow).SprintFunc()
			log.WithFields(log.Fields{
				"name": name,
				"from": from,
				"to":   to,
			}).Debug(c("Ignore module"))
			return true
		}
	}
	return false
}

// nameBudget caps how much of the terminal the name column may claim. One
// unusually long module path would otherwise pad every row to its width and
// leave no room for anything after it.
const nameBudget = 0.55

// columnWidths returns the widths needed to align the name and current
// version columns. Names are measured with DisplayName, since FormatName
// writes colour escapes that would otherwise be counted as visible.
func columnWidths(modules []module.Module) (maxName, maxFrom int) {
	for _, x := range modules {
		maxName = max(maxName, len(x.DisplayName()))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
	if limit := int(float64(terminalWidth()) * nameBudget); maxName > limit {
		maxName = limit
	}
	return maxName, maxFrom
}

// terminalWidth reports the width of the output, falling back to a
// conventional one when it is not a terminal so that a redirected listing is
// still readable.
func terminalWidth() int {
	if w, _, err := xterm.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// terminalHeight reports the height of the output, falling back to a
// conventional one when it is not a terminal.
func terminalHeight() int {
	if _, h, err := xterm.GetSize(int(os.Stdout.Fd())); err == nil && h > 0 {
		return h
	}
	return 24
}

// pageRows converts the --pagesize value into a number of rows to show.
//
// A value of one or below is a share of the terminal height, so the prompt
// grows with the window; anything above one is that many rows. Some of the
// height belongs to the question, the filter help and the shell prompt that
// follows, so a share is taken of what is left rather than of the whole.
func pageRows(pageSize float64) int {
	const (
		reserved = 5
		minRows  = 3
	)
	available := max(terminalHeight()-reserved, 0)
	switch {
	case pageSize > 1:
		return int(pageSize)
	case pageSize > 0:
		return max(int(float64(available)*pageSize), minRows)
	default:
		// Zero or negative is meaningless, so fall back to the default share.
		return max(int(float64(available)*DefaultPageSize), minRows)
	}
}

// layout holds the width of each column, keyed by column name, shared by every
// row of a listing.
type layout struct {
	// width is what each column takes. A column absent from the set has no
	// entry, and one whose modules are all empty has a width of zero.
	width map[string]int
	// columns is what to render, in order.
	columns []string
	// headers reports whether a heading row precedes the listing, which also
	// decides whether the versions are separated by an arrow: with FROM and TO
	// named above them, the arrow is punctuation rather than information.
	headers bool
}

// budget is how wide a listing may be, and whether it is bounded at all.
type budget struct {
	columns int
	limited bool
}

// cell returns the text of one column for a module, without colour escapes,
// which is what a caller measures.
func cell(mod module.Module, column string) string {
	switch column {
	case module.ColumnName:
		return mod.DisplayName()
	case module.ColumnLabel:
		return mod.LabelText()
	case module.ColumnVuln:
		return strings.Join(mod.Vulns, ", ")
	case module.ColumnFrom:
		// Where the workspace members disagree, every version they require. One row
		// stands for all of them here, so naming only the oldest reports the members
		// ahead of it as further behind than they are.
		if joined := module.JoinVersions(mod.Required); joined != "" {
			return joined
		}
		return module.VersionText(mod.From)
	case module.ColumnTo:
		return module.VersionText(mod.To)
	case module.ColumnHint:
		return mod.HintText()
	case module.ColumnCooldown:
		return mod.RemainingText()
	case module.ColumnAge:
		return mod.AgeText()
	case module.ColumnReleaseDate:
		return mod.ReleaseText()
	case module.ColumnTags:
		return module.JoinPaths(mod.Tags)
	case module.ColumnRequiredBy:
		return module.JoinPaths(mod.RequiredBy)
	default:
		return ""
	}
}

// field returns the text of one column for a module as a parser reads it: the
// value in full, canonically spelled, and never empty.
//
// Where cell renders for a person, this renders for a program, and the two differ
// in more than padding. A duration reads "3d" because that is what a reader acts
// on, having rounded away the hours; here it is a count of seconds, which is exact
// and compares as it stands. Labels read as letters to fit a narrow column; here
// they are the --labels keys those letters abbreviate. A pseudo-version shows as
// the commit it names; here it is the version, which is what resolves.
//
// An empty value becomes emptyField so that every column yields exactly one
// whitespace-delimited field on every row: a blank cell would otherwise emit no
// field at all, and the columns after it would answer to a different number in
// every row that happened to carry less.
func field(mod module.Module, column string) string {
	text := ""
	switch column {
	case module.ColumnLabel:
		text = mod.LabelKeys()
	case module.ColumnVuln:
		text = strings.Join(mod.Vulns, valueSeparator)
	case module.ColumnFrom:
		text = mod.From.String()
	case module.ColumnTo:
		text = mod.To.String()
	case module.ColumnCooldown:
		text = mod.RemainingSeconds()
	case module.ColumnAge:
		text = mod.AgeSeconds()
	case module.ColumnTags:
		text = joinFields(mod.Tags)
	case module.ColumnRequiredBy:
		text = joinFields(mod.RequiredBy)
	default:
		// The rest read the same either way: a name, a date and a hint carry no
		// abbreviation to undo.
		text = cell(mod, column)
	}
	if text == "" {
		return emptyField
	}
	return text
}

// joinFields writes a list of paths as one field, so that a cell holding several
// values is still a single one.
//
// Comma-separated without a space, since a space is what separates fields: the
// twenty-four advisories against one module were twenty-four fields, which made
// the columns after them land in a different place on that row than on every
// other.
func joinFields(values []string) string {
	return strings.Join(values, valueSeparator)
}

const (
	// fieldSeparator stands between two fields of a parseable row. A tab, so that
	// cut -f and awk -F'\t' both address the columns, and awk's default splitting
	// on whitespace addresses them too.
	fieldSeparator = "\t"
	// valueSeparator stands between two values within one field, a module path and
	// an advisory identifier both being unable to contain it.
	valueSeparator = ","
	// emptyField is what a column with nothing to say writes, there being no such
	// thing as an empty field in a whitespace-delimited row.
	emptyField = "-"
)

// render returns one column for a module, coloured and padded to width.
func render(mod module.Module, column string, width int) string {
	switch column {
	case module.ColumnName:
		return mod.FormatName(width)
	case module.ColumnLabel:
		return mod.FormatLabels(width)
	case module.ColumnVuln:
		return padRight(mod.FormatVulns(width), width, len(cell(mod, column)))
	case module.ColumnFrom:
		// The joined versions are padded rather than split into the changed and
		// unchanged parts, there being no one version here for the colour to
		// compare against the upgrade.
		if joined := module.JoinVersions(mod.Required); joined != "" {
			return padRight(mod.FormatRequired(joined), width, len(joined))
		}
		return mod.FormatFrom(width)
	case module.ColumnTo:
		return mod.FormatTo(width)
	case module.ColumnHint:
		return padRight(mod.FormatHint(width), width, len(cell(mod, column)))
	case module.ColumnCooldown:
		return module.FormatCooldown(mod.RemainingText(), width)
	case module.ColumnAge:
		return module.FormatCooldown(mod.AgeText(), width)
	case module.ColumnReleaseDate:
		return module.FormatCooldown(mod.ReleaseText(), width)
	case module.ColumnTags:
		return mod.FormatTags(width)
	case module.ColumnRequiredBy:
		return mod.FormatRequiredBy(width)
	default:
		return ""
	}
}

// measure sizes the columns for a set of modules. The extra argument reserves
// room a caller needs for something of its own, such as the prompt's marker.
//
// A column every module leaves empty is dropped: a heading with nothing under it
// is only noise. The last column takes whatever the terminal leaves, since its
// content is the most expendable.
func measure(modules []module.Module, extra int, columns module.Columns, headers bool, b budget) layout {
	l := layout{width: map[string]int{}, headers: headers}

	wanted := columns.Ordered()
	for _, column := range wanted {
		width := 0
		for _, mod := range modules {
			width = max(width, len(cell(mod, column)))
		}
		if width == 0 {
			// No module fills it, so the column is not rendered at all. This is
			// decided before a heading is measured: a heading over an empty
			// column is noise, and letting one set the width would keep every
			// column alive whenever headings are on.
			continue
		}
		// A heading needs room even when the widest value is narrower.
		if headers {
			width = max(width, len(module.Heading(column)))
		}
		l.width[column] = width
		l.columns = append(l.columns, column)
	}

	if !b.limited {
		// Unlimited: every column keeps its natural width, so nothing is capped
		// or elided and the row is as wide as its content needs.
		return l
	}

	// The name column is capped so one unusually long path cannot pad every row
	// to its width and leave no room for anything after it.
	if width, ok := l.width[module.ColumnName]; ok {
		if limit := int(float64(b.columns) * nameBudget); width > limit {
			l.width[module.ColumnName] = limit
		}
	}

	// The trailing column takes what is left, since its content is the most
	// expendable. It keeps its natural width when there is room to spare.
	if len(l.columns) > 1 {
		last := l.columns[len(l.columns)-1]
		if last == module.ColumnRequiredBy || last == module.ColumnHint {
			used := extra
			for _, column := range l.columns[:len(l.columns)-1] {
				used += l.width[column] + gap(column, l.headers)
			}
			l.width[last] = min(l.width[last], max(b.columns-used, 0))
		}
	}
	return l
}

// gap returns the separator width after a column. The versions are joined by an
// arrow unless a heading names them, in which case it is punctuation standing
// between two labelled columns.
func gap(column string, headers bool) int {
	if column == module.ColumnFrom && !headers {
		return len(versionArrow)
	}
	return len(columnGap)
}

const (
	// columnGap separates two columns.
	columnGap = "  "
	// versionArrow joins the two versions when no heading names them.
	versionArrow = " -> "
)

// header renders the heading row for a layout.
//
// The last heading is not padded, for the same reason a row's last column is not:
// trailing blanks are invisible on a terminal but not in a file.
func header(l layout) string {
	var b strings.Builder
	for i, column := range l.columns {
		if i > 0 {
			b.WriteString(separator(l.columns[i-1], l.headers))
		}
		width := 0
		if i < len(l.columns)-1 {
			width = l.width[column]
		}
		b.WriteString(module.FormatHeading(module.Heading(column), width))
	}
	return b.String()
}

// separator returns the text between two columns.
func separator(after string, headers bool) string {
	if after == module.ColumnFrom && !headers {
		return versionArrow
	}
	return columnGap
}

// row renders one module across the columns of a layout.
//
// A column holds its width so that the next one aligns, which means the last
// column with content on a given row needs no padding, and the empty columns
// after it need rendering at all. Emitting them would leave trailing blanks:
// invisible on a terminal, but not in a redirected listing.
func row(mod module.Module, l layout) string {
	// Find where this row's content ends, which is not necessarily where the
	// layout does: a module with no advisory and nothing requiring it leaves the
	// trailing columns empty however wide they are for other rows.
	last := -1
	for i, column := range l.columns {
		if cell(mod, column) != "" {
			last = i
		}
	}

	var b strings.Builder
	for i, column := range l.columns[:last+1] {
		if i > 0 {
			b.WriteString(separator(l.columns[i-1], l.headers))
		}
		width := l.width[column]
		if i == last {
			// Nothing follows on this row, so there is nothing to align and the
			// column needs no padding. It is rendered at exactly its own size
			// rather than at zero: a width is also what a column elides against,
			// so asking for none would truncate the value to nothing.
			width = len(cell(mod, column))
		}
		b.WriteString(render(mod, column, width))
	}
	return b.String()
}

// padRight widens text to a column, given how much of it is visible. The
// rendered text carries colour escapes, which cannot be counted.
func padRight(text string, width, visible int) string {
	if visible >= width {
		return text
	}
	return text + strings.Repeat(" ", width-visible)
}

// fieldRow renders one module as a parseable row: every column of the set, in
// order, one field each.
//
// Nothing here consults a width. A parser is not reading a terminal, so there is
// nothing to fit and nothing to align, and every way of fitting a value loses
// part of it: dropping a column that no module fills, stopping at the last
// column with content, eliding a long list to "+3 more". Each of those made the
// field count depend on what a row happened to carry.
func fieldRow(mod module.Module, columns []string) string {
	fields := make([]string, 0, len(columns))
	for _, column := range columns {
		fields = append(fields, field(mod, column))
	}
	return strings.Join(fields, fieldSeparator)
}

// fieldHeader names the columns of a parseable listing, one field each, so that a
// heading can be addressed by the same index as the rows under it.
func fieldHeader(columns []string) string {
	names := make([]string, 0, len(columns))
	for _, column := range columns {
		names = append(names, module.Heading(column))
	}
	return strings.Join(names, fieldSeparator)
}

// upgradable returns the modules that may be offered for upgrade.
//
// A module matching --ignore is withheld here rather than at discovery, so that
// a policy has already seen it: declining an upgrade is not the same as
// exempting a module from review. A module already at its newest version is
// withheld for the same reason: discovery keeps it so the policy can judge it,
// but there is nothing to offer.
//
// The toolchain row is withheld too. It reports a standard library advisory and
// the release fixing it, but "go get" cannot move the go directive, so offering
// it would run an upgrade that silently did nothing.
// cooling counts the modules held back only because their release is still settling.
//
// Reported alongside "All modules are up to date" to tell the two reasons apart: nothing newer
// exists, or something newer exists and is being waited on. Only the second is answered by
// --cooldown=0.
func countCooling(modules []module.Module) int {
	// Counted as the difference the cooldown makes rather than by repeating the conditions
	// upgradable applies, so the number cannot come to disagree with the list it explains.
	return len(upgradable(modules, true)) - len(upgradable(modules, false))
}

func upgradable(modules []module.Module, cooling bool) []module.Module {
	kept := make([]module.Module, 0, len(modules))
	for _, mod := range modules {
		if mod.Name == ToolchainName {
			continue
		}
		// A release still settling is not recommended, so it is not offered unless
		// the caller asked for it. This gate is separate from the listing's filter,
		// which the interactive path never passes through: withholding a module from
		// --list and then offering it in the prompt would be the mismatch.
		if !cooling && mod.Cooling() {
			continue
		}
		if !mod.Ignored && !mod.From.Equal(mod.To) {
			kept = append(kept, mod)
		}
	}
	return kept
}

// stdout is where a listing is written.
//
// A variable rather than os.Stdout directly, so a test can read what a format
// wrote. The parseable formats address it: colour goes to color.Output, which
// strips the escapes when the destination is not a terminal.
var stdout io.Writer = os.Stdout

// present writes the listing in the requested format.
//
// The rows are split into one per requirement before the filter runs, so that a
// filter selects over the rows a reader is shown. Filtering the merged row asked
// the question of a version no member requires: a workspace member standing past
// everything published makes a row a downgrade, while the merged row it came from
// is an ordinary upgrade, so --labels=downgrade withheld a row the listing printed.
//
// This reverses the rule listModules stated, that the fanout belongs where the rows
// are printed and only there. It holds for the configuration fanout, which is a
// presentation of one requirement and stays in the writers. It does not hold for
// the requirement split, which decides what a row is about.
//
// Combining the rows again is left to the formats wanting one row per module, after
// the filter and the sort have both had them.
func present(modules []module.Module, v view) error {
	modules = module.Apply(module.PerRequirement(modules), v.filter)
	switch v.format {
	case module.FormatPolicy:
		return module.WritePolicy(stdout, module.Coalesce(modules))
	case module.FormatJSON:
		return module.WriteJSON(stdout, module.Coalesce(modules))
	case module.FormatTSV:
		listFields(modules, v)
		return nil
	default:
		listModules(modules, v)
		return nil
	}
}

// listFields writes the modules as parseable rows, one field per column.
//
// The columns are those asked for, not those that turned out to have content: a
// parser addresses a column by position, so the set cannot depend on the rows.
func listFields(modules []module.Module, v view) {
	// Split by configuration alone. The rows arrive one per requirement, present
	// having split them before the filter, since a parser reads one requirement per
	// row and a cell naming several versions is not a version.
	modules = module.PerConfiguration(modules)
	slices.SortStableFunc(modules, v.sort.Compare)

	columns := v.columns.Ordered()
	if len(columns) == 0 {
		return
	}
	// Written to stdout rather than color.Output: there is no colour in a
	// parseable row, and nothing to strip on the way out.
	if v.headers {
		if _, err := fmt.Fprintln(stdout, fieldHeader(columns)); err != nil {
			log.WithError(err).Error("Error while writing the heading")
		}
	}
	for _, x := range modules {
		if _, err := fmt.Fprintln(stdout, fieldRow(x, columns)); err != nil {
			log.WithFields(log.Fields{"error": err, "name": x.Name}).
				Error("Error while listing module")
		}
	}
}

func listModules(modules []module.Module, v view) {
	// Sorted while the requirements are still separate rows, since that is what the
	// reader asked to order: --sort works over the rows a filter kept, and ordering
	// the combined row would sort a workspace by a version no member requires.
	slices.SortStableFunc(modules, v.sort.Compare)
	// Combined into one row per module, a person reading a workspace wanting one
	// line each. Lossless: the row names every version its rows required and carries
	// every label they earned, so combining hides nothing the split revealed.
	modules = module.Coalesce(modules)
	// One row per configuration reaching a module, so a module several builds
	// reach is listed once for each rather than with a list crammed into one cell.
	// Only here: a configuration is a presentation of one requirement rather than a
	// requirement of its own, so these rows are printed and go no further.
	modules = module.PerConfiguration(modules)
	// Sorted again, since the rows of one module are new and the name alone cannot
	// order them.
	slices.SortStableFunc(modules, v.sort.Compare)

	l := measure(modules, 0, v.columns, v.headers, v.width)
	// The labels need explaining whether or not the columns are titled, so this
	// does not wait on the heading.
	legend(modules)
	if l.headers && len(l.columns) > 0 {
		if _, err := fmt.Fprintln(color.Output, header(l)); err != nil {
			log.WithError(err).Error("Error while writing the heading")
		}
	}
	for _, x := range modules {
		_, err := fmt.Fprintln(color.Output, row(x, l))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while listing module")
		}
	}
}

func choose(modules []module.Module, pageSize float64, columns module.Columns, width budget) []module.Module {
	// The prompt indents each option, so leave room for its marker. The columns are
	// measured with a heading, which the prompt pins above the options.
	l := measure(modules, markerWidth, columns, true, width)
	options := []string{}
	for _, x := range modules {
		options = append(options, row(x, l))
	}

	heading := ""
	if len(l.columns) > 0 {
		heading = header(l)
	}
	legend(modules)
	choice, answered, err := askMulti("Choose which modules to update", heading, options, nil, pageRows(pageSize))
	if err != nil {
		log.WithError(err).Error("Choose failed")
		stop(1)
	}
	if !answered {
		quit()
	}
	updates := []module.Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(ctx context.Context, dir string, modules []module.Module, hook string) {
	for _, x := range modules {
		_, err := fmt.Fprintf(color.Output, "Updating %s to version %s...\n", x.FormatName(len(x.DisplayName())), x.FormatTo(0))
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while updating module")
		}
		// Ask for the version that was reported, rather than letting go get
		// resolve @latest, which may have moved on since discovery. Original
		// keeps the leading "v", which String strips and pseudo-versions need.
		cmd := exec.CommandContext(ctx, "go", "get", x.Name+"@"+x.To.Original())
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
				"out":   string(out),
			}).Error("Error while updating module")
		}
		if hook != "" {
			cmd := exec.CommandContext(
				ctx,
				hook,
				x.Name,
				x.From.String(),
				x.To.String(),
			)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"hook":  hook,
					"out":   string(out),
				}).Error("Error while executing hook")
				stop(1)
			}
			log.Info(string(out))
		}
	}
}
