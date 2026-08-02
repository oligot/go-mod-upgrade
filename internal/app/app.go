package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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

type AppEnv struct {
	Verbose  bool
	Force    bool
	List     bool
	PageSize float64
	Hook     string
	Ignore   []string
	Indirect bool
	All      bool
	Vuln     bool
	Sort     string
	WorkSync bool
	NoColor  bool
	Colors   string
	Filter   string
	Format   string
	// Columns is the -k chain naming which columns a listing shows.
	Columns string
	// Headers asks for a heading row. HeadersSet reports whether the caller
	// said either way, since unset means "when writing to a terminal".
	Headers    bool
	HeadersSet bool
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

// showHeaders reports whether a listing gets a heading row.
//
// A heading helps a person read six columns and hinders anything parsing them, so
// it follows the output by default: on at a terminal, off when redirected. Saying
// either explicitly settles it.
func (app *AppEnv) showHeaders() bool {
	if app.HeadersSet {
		return app.Headers
	}
	return xterm.IsTerminal(int(os.Stdout.Fd()))
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

// scope reports which dependencies the flags ask for.
func (app *AppEnv) scope() scope {
	switch {
	case app.All:
		return scopeAll
	case app.Indirect:
		return scopeIndirect
	default:
		return scopeDirect
	}
}

func (app *AppEnv) Run(ctx context.Context) error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	if app.NoColor {
		color.NoColor = true
	}
	// Resolve the palette and the chain up front so an unusable value fails
	// before any network work has been done.
	if err := module.SetColors(app.Colors); err != nil {
		return err
	}
	// Resolve the chain up front so an unusable key fails before any network
	// work has been done.
	sorter, err := module.ParseSort(app.Sort)
	if err != nil {
		return err
	}
	filter, err := module.ParseFilter(app.Filter, module.DefaultFilters())
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
	// Which columns a listing shows depends on what the flags gathered: an
	// advisory column is only meaningful with --vuln, and what pulls a module in
	// is only computed with --all.
	base := module.DefaultColumns()
	if app.Vuln {
		base = append(base, module.ColumnCVE, module.ColumnHint)
	}
	if app.All {
		base = append(base, module.ColumnRequiredBy)
	}
	// Which configurations reach a module, and so whether any build reaches it at
	// all. Empty when nothing was swept, which measure then drops.
	base = append(base, module.ColumnTags)
	columns, err := module.ParseColumns(app.Columns, base)
	if err != nil {
		return err
	}
	listCols, limited := app.listWidth()
	// A caller with room enough to see everything wants the versions in full
	// rather than abbreviated to a commit.
	module.Wide = !limited
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
		// A policy asking about advisories needs them looked up, so the flags
		// cannot fall out of step with a file the caller may not have written.
		if rules.ScansVulnerabilities() && !app.Vuln {
			log.Info("Policy asks about vulnerabilities, so scanning for them")
			app.Vuln = true
		}
	}
	// Dependent counts are only gathered with --all, so without it that key
	// cannot order anything. Report it rather than sorting arbitrarily.
	if !app.All && slices.Contains(sorter.Keys, module.SortDeps) {
		log.Warn("Sorting by dependents requires --all, so that key is ignored")
	}
	if app.All {
		log.Info("--all can add `// indirect` entries to go.mod; recommend running `go mod tidy` afterwards")
	}
	gw, err := exec.CommandContext(ctx, "go", "env", "GOWORK").Output()
	if err != nil {
		return err
	}
	gowork := strings.TrimSpace(string(gw))
	workspace := gowork != "" && gowork != "off"

	var dirs []string
	if workspace {
		log.WithField("gowork", gowork).Info("Workspace mode")
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
	if workspace && app.All {
		// The members of a workspace share most of their dependencies, so
		// offering each member separately would ask about the same upgrade
		// repeatedly. Gather them into one list instead.
		n, err := app.runWorkspace(ctx, dirs, v)
		if err != nil {
			errs = append(errs, err)
		}
		updated += n
	} else {
		for _, dir := range dirs {
			log.WithField("dir", dir).Info("Scanning")
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
		if status := report(*v.violations); status != 0 {
			errs = append(errs, &PolicyError{Status: status})
		}
	}
	return errors.Join(errs...)
}

// PolicyError reports that a policy refused the run, carrying the status it
// asked to leave with.
type PolicyError struct {
	Status int
}

func (e *PolicyError) Error() string {
	return "policy violations found"
}

// ExitStatus reports the status a run should leave with, which is the one the
// policy asked for when it refused.
func ExitStatus(err error) int {
	var pe *PolicyError
	if errors.As(err, &pe) {
		return pe.Status
	}
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
	var errs []error

	for _, dir := range dirs {
		log.WithField("dir", dir).Info("Scanning")
		discovered, mod, err := discoverModules(ctx, dir, app.Ignore, app.scope())
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
		deps, err := sweep(ctx, "Inspecting "+filepath.Base(dir), filters,
			func(ctx context.Context, f tagFilter) (dependents, error) {
				return reverseDeps(ctx, dir, f)
			})
		if err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
		merged, where := mergeDependents(filters, deps)
		for mod := range merged {
			reached[mod] = struct{}{}
		}
		spread.add(filters, where)

		if app.Vuln {
			// Each member has to be scanned separately: govulncheck needs a
			// go.mod, and the directory holding go.work usually has none.
			swept, err := sweep(ctx, "Scanning "+filepath.Base(dir), filters,
				func(ctx context.Context, f tagFilter) (vulnerabilities, error) {
					return scanVulnerabilities(ctx, dir, f)
				})
			if err != nil {
				return 0, errors.Join(append(errs, err)...)
			}
			mergeVulns(found, mergeAcrossTags(swept))
		}
		for _, m := range discovered {
			members[m.Name] = append(members[m.Name], dir)
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
		modules = append(modules, m)
	}
	// Which configurations reach a module is only worth reporting when the whole
	// graph is on offer, as with the members requiring it.
	if app.All {
		spread.annotate(modules)
	}
	if app.Vuln {
		annotateVulns(modules, found)
		// An advisory in the standard library has no module to attach to, so it
		// is carried by a row of its own naming the toolchain. The oldest
		// version any member declares is the one to report against.
		version := ""
		if oldest != nil {
			version = oldest.String()
		}
		if toolchain, ok := toolchainModule(version, found); ok {
			modules = append(modules, toolchain)
		}
		// Which upgrades resolve an advisory is a property of the candidates'
		// own go.mod files rather than of any one member, so any member's
		// directory can read them.
		if len(dirs) > 0 {
			fixed, err := resolvers(ctx, dirs[0], modules, found, reached)
			if err != nil {
				return 0, errors.Join(append(errs, err)...)
			}
			annotateResolvers(modules, fixed)
		}
	}
	slices.SortStableFunc(modules, v.sort.Compare)
	if v.rules != nil {
		// Annotate before checking, so the listing and the report describe the
		// same modules.
		annotateArchived(v.rules, modules)
		*v.violations = append(*v.violations, enforce(v.rules, modules)...)
	}

	if len(modules) == 0 {
		fmt.Println("All modules are up to date")
		return 0, errors.Join(errs...)
	}
	if app.List {
		if err := present(modules, v); err != nil {
			errs = append(errs, err)
		}
		return 0, errors.Join(errs...)
	}
	modules = upgradable(modules)
	if len(modules) == 0 {
		// Discovery keeps the modules already at their newest version so that a
		// policy can judge them, so reaching here is the ordinary "nothing to
		// do" rather than a module with no requirements.
		fmt.Println("All modules are up to date")
		return 0, errors.Join(errs...)
	}
	if !app.Force {
		modules = choose(modules, app.PageSize, v.columns, v.width)
	} else {
		log.Debug("Update all modules in non-interactive mode...")
	}

	updated := 0
	for _, m := range modules {
		dirs := members[m.Name]
		// A module required by one member has nothing to choose between, and
		// --force takes everything by definition.
		if len(dirs) > 1 && !app.Force {
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
	choice, answered, err := ask(message, "", options, defaults, pageRows(pageSize))
	if err != nil {
		return nil, err
	}
	if !answered {
		log.Info("Bye")
		os.Exit(0)
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
	modules, mod, err := discoverModules(ctx, dir, app.Ignore, app.scope())
	if err != nil {
		return 0, err
	}
	// Which build configurations to analyse. A tag decides which files compile,
	// so analysing only what a plain build sees under-reports whatever the tests
	// or a platform-specific file pull in.
	filters, err := app.configurations(dir)
	if err != nil {
		return 0, err
	}
	if len(filters) > 1 {
		log.WithField("configurations", filterNames(filters)).
			Info("Analysing several build configurations")
	}

	// Which modules contribute a package to the build, under any configuration.
	// An upgrade is only worth suggesting for a module the code actually reaches,
	// so this is gathered whether or not the dependents are being displayed.
	var reached map[string]struct{}
	{
		found, err := sweep(ctx, "Inspecting dependencies", filters,
			func(ctx context.Context, f tagFilter) (dependents, error) {
				return reverseDeps(ctx, dir, f)
			})
		if err != nil {
			return 0, err
		}
		deps, where := mergeDependents(filters, found)
		reached = make(map[string]struct{}, len(deps))
		for mod := range deps {
			reached[mod] = struct{}{}
		}
		if app.All {
			// Which modules an upgrade reaches is only worth reporting when the
			// whole graph is on offer; a direct requirement is reached by the
			// module being worked on and little else is informative.
			for i := range modules {
				modules[i].RequiredBy = deps[modules[i].Name]
			}
			annotateTags(modules, where, len(filters))
		}
	}
	if app.Vuln {
		// A scan that cannot complete reports nothing, which reads exactly
		// like a clean result, so the failure is returned rather than logged.
		found, err := sweep(ctx, "Scanning for vulnerabilities", filters,
			func(ctx context.Context, f tagFilter) (vulnerabilities, error) {
				return scanVulnerabilities(ctx, dir, f)
			})
		if err != nil {
			return 0, err
		}
		vulns := mergeAcrossTags(found)
		annotateVulns(modules, vulns)
		// An advisory in the standard library has no module to attach to, so it
		// is carried by a row of its own naming the toolchain.
		if toolchain, ok := toolchainModule(mod.stdlibVersion(), vulns); ok {
			modules = append(modules, toolchain)
		}
		// Some advisories are resolved by upgrading a dependent rather than the
		// module carrying them, which is worth knowing before acting on a row.
		fixed, err := resolvers(ctx, dir, modules, vulns, reached)
		if err != nil {
			return 0, err
		}
		annotateResolvers(modules, fixed)
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
	}
	if len(modules) == 0 {
		fmt.Println("All modules are up to date")
		return 0, nil
	}
	if app.List {
		return 0, present(modules, v)
	}
	modules = upgradable(modules)
	if len(modules) == 0 {
		// Discovery keeps the modules already at their newest version so that a
		// policy can judge them, so reaching here is the ordinary "nothing to
		// do" rather than a module with no requirements.
		fmt.Println("All modules are up to date")
		return 0, nil
	}
	if !app.Force {
		modules = choose(modules, app.PageSize, v.columns, v.width)
	} else {
		log.Debug("Update all modules in non-interactive mode...")
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
	cmd.Env = append(os.Environ(), "GOWORK=off")
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
		updateCmd.Env = append(os.Environ(), "GOWORK=off")
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
	case module.ColumnCVE:
		return strings.Join(mod.Vulns, ", ")
	case module.ColumnFrom:
		return module.VersionText(mod.From)
	case module.ColumnTo:
		return module.VersionText(mod.To)
	case module.ColumnHint:
		return mod.HintText()
	case module.ColumnTags:
		return module.JoinPaths(mod.Tags)
	case module.ColumnRequiredBy:
		return module.JoinPaths(mod.RequiredBy)
	default:
		return ""
	}
}

// render returns one column for a module, coloured and padded to width.
func render(mod module.Module, column string, width int) string {
	switch column {
	case module.ColumnName:
		return mod.FormatName(width)
	case module.ColumnLabel:
		return mod.FormatLabels(width)
	case module.ColumnCVE:
		return padRight(mod.FormatVulns(width), width, len(cell(mod, column)))
	case module.ColumnFrom:
		return mod.FormatFrom(width)
	case module.ColumnTo:
		return mod.FormatTo(width)
	case module.ColumnHint:
		return padRight(mod.FormatHint(width), width, len(cell(mod, column)))
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
func upgradable(modules []module.Module) []module.Module {
	kept := make([]module.Module, 0, len(modules))
	for _, mod := range modules {
		if mod.Name == ToolchainName {
			continue
		}
		if !mod.Ignored && !mod.From.Equal(mod.To) {
			kept = append(kept, mod)
		}
	}
	return kept
}

// present writes the listing in the requested format.
//
// A filter is applied first, so what is written is what was asked for whichever
// representation carries it.
func present(modules []module.Module, v view) error {
	modules = module.Apply(modules, v.filter)
	switch v.format {
	case module.FormatPolicy:
		return module.WritePolicy(os.Stdout, modules)
	case module.FormatJSON:
		return module.WriteJSON(os.Stdout, modules)
	default:
		listModules(modules, v)
		return nil
	}
}

func listModules(modules []module.Module, v view) {
	// One row per configuration reaching a module, so a module several builds
	// reach is listed once for each rather than with a list crammed into one cell.
	// Only here: the rows are printed and go no further, so a duplicate cannot
	// reach the prompt, the policy gate, or an upgrade.
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
	l := measure(modules, 6, columns, true, width)
	options := []string{}
	for _, x := range modules {
		options = append(options, row(x, l))
	}

	heading := ""
	if len(l.columns) > 0 {
		heading = header(l)
	}
	legend(modules)
	choice, answered, err := ask("Choose which modules to update", heading, options, nil, pageRows(pageSize))
	if err != nil {
		log.WithError(err).Error("Choose failed")
		os.Exit(1)
	}
	if !answered {
		log.Info("Bye")
		os.Exit(0)
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
				os.Exit(1)
			}
			log.Info(string(out))
		}
	}
}
