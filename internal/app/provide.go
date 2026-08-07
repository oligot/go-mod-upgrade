package app

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/apex/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// Asking a question requires answering it.
//
// A column and a label key that name the same property are two reasons to want one
// answer, not two subsystems: --columns=+vuln displays "does this module carry an
// advisory?" and --labels=+vuln selects on it, and both need it looked up. Reading the
// selectors as display filters over whatever the flags happened to gather is what made
// asking for something nothing gathered yield silence -- measure drops a column no
// module fills, so a column never populated is indistinguishable from one every module
// left empty.
//
// So the work a run does is derived from what was asked of it. This file holds the
// derivation: what each column needs answered, and how to answer it once however many
// callers ask.

// cost says whether answering a column costs anything beyond what discovery already pays.
//
// Recorded so the registry states it rather than leaving it to be inferred from the
// provider's body. What is free is free because something else already needed it: the
// import-graph sweep runs to decide which modules the build reaches, so the columns
// reading its result are map lookups over data already gathered. Gating those was
// defect 1 -- withholding what had already been paid for.
type cost int

const (
	// free is answered by work discovery does anyway; paid runs a command of its own.
	free cost = iota
	paid
)

// buildAt is one directory and the build configurations to analyse it under.
//
// Paired because a configuration decides which files compile and so which modules the
// build reaches, and workspace members declare their own. Analysing every member under
// one member's tags would report a build no member has.
type buildAt struct {
	dir     string
	filters []tagFilter
}

// site is what one filling works on: where to look, what to annotate, and what the
// answers other phases need are written back to.
//
// The modules are a pointer because a provider can add a row rather than only annotate
// one -- an advisory in the standard library has no module to attach to, so it arrives
// as a row of its own. That is also what makes the memo's guarantee meaningful: appending
// a toolchain row is not idempotent, so what is remembered has to be the application
// rather than the fact.
type site struct {
	// at is the directory to work in, or every member of a workspace.
	at []buildAt
	// into is the rows to annotate, and to append a row to.
	into *[]module.Module
	// found accumulates the advisories, which the policy gate reads after the
	// listing: an upgrade is refused for the advisories it would land, and that
	// needs the fix versions a row does not carry.
	found *vulnerabilities
	// reached names the modules contributing a package to the build, from the sweep
	// discovery already ran. An upgrade is only worth suggesting for a module the
	// code reaches, so a resolver is only looked for among those.
	reached map[string]struct{}
	// stdlib is the toolchain version a standard library advisory is reported
	// against -- for a workspace, the oldest any member declares, that being the
	// version the advisory is worst in.
	stdlib string
}

// dirs names the directories a site covers.
func (s site) dirs() []string {
	out := make([]string, 0, len(s.at))
	for _, at := range s.at {
		out = append(out, at.dir)
	}
	return out
}

// filling is what answering one column takes.
type filling struct {
	cost cost
	// provide answers the column, nil where discovery already fills it.
	provide func(context.Context, *AppEnv, site) error
}

// fillings says, for every column, what answering it takes.
//
// Exhaustive over columnOrder, no-ops included. Totality is the point rather than
// topology: a column with no entry is a question that silently goes unanswered, which
// is the defect class this file exists to close, and a test over ColumnNames() can only
// catch that if every column is required to declare itself. So the free entries are
// written out rather than defaulted.
//
// There is no dependency graph here. recall is idempotent, so a provider needing
// another's answer calls it -- the hint provider calls the vuln provider, a memo hit when
// vuln was demanded too and one scan when it was not. The dependency falls out of the
// call graph, which is why no node registry, topological sort or cycle check exists.
//
// A function rather than a variable because that call graph closes a loop through here:
// the hint provider calls fill, which reads the registry. As a package-level variable
// that is an initialization cycle the compiler refuses, and the alternatives -- filling
// the paid entries in an init, or having a provider reach past fill to the memo -- would
// either split the registry that totality is checked against or duplicate the memo key
// that makes the work happen once.
func fillings() map[string]filling {
	return map[string]filling{
		// Discovery reads the versions and how each module is required, and the release
		// dates come with them.
		module.ColumnName:        {cost: free},
		module.ColumnLabel:       {cost: free},
		module.ColumnFrom:        {cost: free},
		module.ColumnTo:          {cost: free},
		module.ColumnReleaseDate: {cost: free},
		module.ColumnCooldown:    {cost: free},
		module.ColumnAge:         {cost: free},
		// Both read the import-graph sweep, which runs to decide what the build reaches.
		module.ColumnRequiredBy: {cost: free},
		module.ColumnTags:       {cost: free},
		// A scan, and what the scan makes resolvable elsewhere.
		module.ColumnVuln: {cost: paid, provide: provideVulns},
		module.ColumnHint: {cost: paid, provide: provideResolvers},
	}
}

// fillArgs identifies one application of one filling, and so is what the memo files it
// under.
//
// Where the other memo keys carry the arguments a gatherer is called with, this carries
// what identifies the application: the site itself cannot be a key, holding slices and a
// map, and what has to happen exactly once is the mutation rather than the lookup. The
// facts underneath are memoized on their own keys already, so a second asking here costs
// a map lookup and the answers it would have gathered are hits.
//
// The target pointer is part of the key because two listings are two things to annotate.
type fillArgs struct {
	column string
	// dirs and tags are the site's directories and configurations, joined, so two
	// asks about the same work share an answer and one about different work does not.
	dirs string
	tags string
	into *[]module.Module
}

// args returns the key one filling of a column at this site is remembered by.
func (s site) args(column string) fillArgs {
	var tags []string
	for _, at := range s.at {
		for _, f := range at.filters {
			tags = append(tags, at.dir+"\x00"+f.String())
		}
	}
	return fillArgs{
		column: column,
		dirs:   strings.Join(s.dirs(), "\x00"),
		tags:   strings.Join(tags, "\x1f"),
		into:   s.into,
	}
}

// fill answers a column, once however many callers ask.
//
// Routed through recall so exactly-once is the memo's guarantee rather than a second
// mechanism with its own bugs. A column discovery already fills is a no-op, and is
// looked up rather than special-cased so that whether work happens is decided in the
// registry.
func (app *AppEnv) fill(ctx context.Context, column string, s site) error {
	f, ok := fillings()[column]
	if !ok {
		// Unreachable while TestEveryColumnDeclaresItsWork passes. Reported rather
		// than asserted: a column added without an entry should render empty, which
		// is what it did before, rather than end the run.
		log.WithField("column", column).
			Debug("No filling declares what this column takes, so nothing gathers it")
		return nil
	}
	if f.provide == nil {
		return nil
	}
	log.WithFields(log.Fields{"column": column, "dirs": strings.Join(s.dirs(), ", ")}).
		Debug("Gathering what a column needs")
	_, err := recall(app.answers, s.args(column), func(fillArgs) (struct{}, error) {
		return struct{}{}, f.provide(ctx, app, s)
	})
	return err
}

// provideVulns scans for the advisories affecting the site and attaches them.
//
// Each directory is scanned separately: govulncheck needs a go.mod, and the directory
// holding go.work usually has none.
func provideVulns(ctx context.Context, app *AppEnv, s site) error {
	for _, at := range s.at {
		// A scan that cannot complete reports nothing, which reads exactly like a
		// clean result, so the failure is returned rather than logged.
		swept, err := sweep(ctx, scanLabel(at.dir, s), at.filters,
			func(ctx context.Context, f tagFilter) (vulnerabilities, error) {
				return app.advisories(ctx, at.dir, f)
			})
		if err != nil {
			return err
		}
		mergeVulns(*s.found, mergeAcrossTags(swept))
	}
	annotateVulns(*s.into, *s.found)
	// An advisory in the standard library has no module to attach to, so it is
	// carried by a row of its own naming the toolchain.
	if toolchain, ok := toolchainModule(s.stdlib, *s.found); ok {
		*s.into = append(*s.into, toolchain)
	}
	return nil
}

// provideResolvers works out which upgrades would resolve an advisory elsewhere.
//
// Some advisories are resolved by upgrading a dependent rather than the module carrying
// them, which is worth knowing before acting on a row: the row to take is the one
// advertising that it clears a finding, not the row reporting the finding.
//
// The scan is asked for rather than assumed, so demanding the hint alone still answers
// what it needs. A run that demanded the advisories too finds this a memo hit.
func provideResolvers(ctx context.Context, app *AppEnv, s site) error {
	if err := app.fill(ctx, module.ColumnVuln, s); err != nil {
		return err
	}
	dirs := s.dirs()
	if len(dirs) == 0 {
		return nil
	}
	// Which upgrades resolve an advisory is a property of the candidates' own go.mod
	// files rather than of any one member, so any member's directory can read them.
	fixed, err := resolvers(ctx, dirs[0], *s.into, *s.found, s.reached)
	if err != nil {
		return err
	}
	annotateResolvers(*s.into, fixed)
	return nil
}

// scanLabel names the scan a progress counter reports, saying which member is being
// scanned only where there is more than one.
func scanLabel(dir string, s site) string {
	if len(s.at) == 1 {
		return "Scanning for vulnerabilities"
	}
	return "Scanning " + filepath.Base(dir)
}

// demands returns the columns whose answers this run needs gathered.
//
// The union of what the selectors read: the columns a listing shows, plus the property
// every --labels key names whichever sign it carried. Selection and display are two
// consumers of one question, so a run that hides the modules carrying an advisory does
// the same scan as one that lists them -- knowing which to hide is the same lookup.
//
// Nothing comes from --sort. DefaultSorts orders by fixes and by advisories, so a
// blanket sort-implies-demand rule would make every default run scan for
// vulnerabilities. An ordering is over the rows there are; it asks for nothing.
//
// A demand is not a column: the set returned decides what work happens, and what a
// listing shows is decided by the columns as parsed. So this starts from an empty set
// rather than from those, and a chain that named its columns outright still demands
// what it named.
func (app *AppEnv) demands(v view) module.Columns {
	want := module.Columns{}
	for _, column := range v.columns.Ordered() {
		want = want.With(column)
	}
	for _, key := range v.filter.Keys() {
		for _, column := range answering[key] {
			want = want.With(column)
		}
	}
	// A policy asking about advisories needs them looked up, so a file the caller may
	// not have written cannot fall out of step with the flags. Read from the rules
	// rather than recorded on a flag when the policy loads: a flag set after the
	// columns were resolved was set too late to be seen, which rendered a scan's
	// result nowhere.
	if v.rules != nil && v.rules.ScansVulnerabilities() {
		want = want.With(module.ColumnVuln)
	}
	return want
}

// answering maps a --labels key to the columns whose work answers it.
//
// Only the keys naming something gathered appear. A key selecting on what discovery
// already read -- how a module is required, whether an upgrade exists -- needs no entry,
// there being no work to trigger, and one selecting on a wider scope is scope's to
// decide rather than demand's.
var answering = map[string][]string{
	// Both need the scan. Whether the vulnerable code is reached is what the scan
	// reports, so selecting on either sense asks the same question.
	module.FilterVulnReachable: {module.ColumnVuln},
	module.FilterVulnPresent:   {module.ColumnVuln},
	// Both read what the resolvers pass attaches: which upgrade would fix this
	// module, and what this module's upgrade would fix.
	module.FilterFixes:      {module.ColumnHint},
	module.FilterTransitive: {module.ColumnHint},
}
