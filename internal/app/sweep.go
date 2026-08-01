package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/apex/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// tagArgs returns the -tags argument for a configuration, or nothing for the
// default one. A bare "-tags=" is not the same as omitting it, so the empty case
// passes no flag at all.
func (f tagFilter) tagArgs() []string {
	if len(f.tags) == 0 {
		return nil
	}
	return []string{"-tags=" + strings.Join(f.tags, ",")}
}

// sweep runs one pass per build configuration and merges what each reports.
//
// A build tag decides which files compile, and so which modules the build reaches
// and which of their code it calls. Analysing one configuration therefore
// under-reports: in a project whose tests hide behind a tag, the dependencies
// those tests pull in are invisible to a plain build. Which configuration is the
// interesting one is not the caller's to guess, so every one the project declares
// is swept and the findings are combined.
//
// The passes are independent, so they run concurrently, and the counter reports
// completions as they land.
func sweep[T any](
	ctx context.Context,
	label string,
	filters []tagFilter,
	pass func(context.Context, tagFilter) (T, error),
) ([]T, error) {
	if len(filters) == 0 {
		return nil, nil
	}

	c, err := track(label, len(filters))
	if err != nil {
		return nil, err
	}
	defer c.Stop()

	type result struct {
		at    int
		value T
		err   error
	}
	results := make(chan result, len(filters))
	for i, f := range filters {
		go func() {
			value, err := pass(ctx, f)
			c.step()
			results <- result{at: i, value: value, err: err}
		}()
	}

	out := make([]T, len(filters))
	// A pass lands when it finishes rather than in the order the configurations
	// were given, so failures are held by position and joined afterwards. The same
	// input then reports the same thing however the passes happened to finish.
	errs := make([]error, len(filters))
	for range filters {
		r := <-results
		if r.err != nil {
			// One configuration failing says nothing about the others, so the
			// rest are still reported. Every error is kept: a caller deciding
			// whether a tree is clean must not read a failed pass as a clean one,
			// and one broken configuration does not explain another.
			errs[r.at] = fmt.Errorf("%s: %w", filters[r.at], r.err)
			continue
		}
		out[r.at] = r.value
	}
	c.Stop()
	return out, errors.Join(errs...)
}

// reachedIn records which configurations reach each module, so a listing can say
// a module is only in the build under some of them.
type reachedIn map[string][]string

// note records that a configuration reached a module.
func (r reachedIn) note(mod string, f tagFilter) {
	name := f.String()
	if !slices.Contains(r[mod], name) {
		r[mod] = append(r[mod], name)
	}
}

// mergeDependents folds what several configurations reported about who imports
// what into one graph, and records which configurations reached each module.
//
// A module reached under one configuration and not another is still a module the
// project can build against, so the union is what a listing shows. Which
// configurations reached it is kept alongside, since that is the more useful
// statement: "only under integration" says something "reached" does not.
func mergeDependents(filters []tagFilter, found []dependents) (dependents, reachedIn) {
	merged := dependents{}
	where := reachedIn{}
	for i, deps := range found {
		if i >= len(filters) {
			break
		}
		for mod, importers := range deps {
			where.note(mod, filters[i])
			for _, importer := range importers {
				if !slices.Contains(merged[mod], importer) {
					merged[mod] = append(merged[mod], importer)
				}
			}
		}
	}
	for mod := range merged {
		slices.Sort(merged[mod])
	}
	return merged, where
}

// mergeAcrossTags folds the advisories found under several configurations into
// one set.
//
// An advisory reachable under any configuration is reachable, since a caller
// building that way runs the code. So reachability is the union: a finding
// reached in one pass and merely present in another counts as reached.
func mergeAcrossTags(found []vulnerabilities) vulnerabilities {
	merged := vulnerabilities{}
	for _, vulns := range found {
		mergeVulns(merged, vulns)
	}
	return merged
}

// annotateTags records against each module the configurations that reach it,
// leaving the field empty when every configuration does.
//
// A listing shows the column only when it distinguishes something: if the whole
// build list is reached whatever the tags, saying so on every row is noise.
func annotateTags(modules []module.Module, where reachedIn, total int) {
	for i := range modules {
		reached := where[modules[i].Name]
		if len(reached) == 0 || len(reached) == total {
			continue
		}
		modules[i].Tags = slices.Sorted(slices.Values(reached))
	}
	log.WithFields(log.Fields{
		"configurations": total,
		"modules":        len(modules),
	}).Debug("Recorded which configurations reach each module")
}

// tagSpread gathers, across a workspace, the configurations that reach each
// module.
//
// Every configuration reaching a module is named, so a blank column says one
// thing: no build reaches the module at all. That is worth saying plainly -- it
// marks a requirement nothing imports -- and it is what naming the configurations
// only when they differed used to obscure, a module reached under all of them
// reading the same as one reached under none.
//
// Members declare their own tags and so sweep their own configurations, which is
// why the names are unioned: each is a way the workspace does build the module.
type tagSpread struct {
	// reached holds every configuration that reached a module, across members. A
	// set, since the names are unordered and each is wanted once; annotate orders
	// them for display.
	reached map[string]map[string]struct{}
	// conditional holds the modules some member reached under only part of what it
	// swept. A module no member found conditional is unconditional across the
	// workspace, which a capped listing reports as "*" rather than by naming every
	// configuration swept.
	conditional map[string]struct{}
}

func newTagSpread() *tagSpread {
	return &tagSpread{
		reached:     map[string]map[string]struct{}{},
		conditional: map[string]struct{}{},
	}
}

// note records that a configuration reached a module.
func (s *tagSpread) note(mod, name string) {
	if s.reached[mod] == nil {
		s.reached[mod] = map[string]struct{}{}
	}
	s.reached[mod][name] = struct{}{}
}

// add records what one member's sweep reached, out of the configurations it swept.
func (s *tagSpread) add(filters []tagFilter, where reachedIn) {
	for mod, reached := range where {
		if len(reached) == 0 {
			continue
		}
		for _, name := range reached {
			s.note(mod, name)
		}
		if len(reached) == len(filters) {
			// Reached whatever this member sets, so none of its configurations
			// distinguishes the module. Recorded all the same, since a listing with
			// room says which were swept.
			continue
		}
		s.conditional[mod] = struct{}{}
		// A configuration that reaches the module says what to set to keep it. When
		// none of them sets anything and another configuration was swept, the plain
		// build alone does not say what loses it, so what excludes it is named
		// alongside.
		if !slices.ContainsFunc(reached, setsTags) {
			if name, ok := excludedBy(filters, reached); ok {
				s.note(mod, name)
			}
		}
	}
}

// excludedBy names what keeps a module out of the build, as the negation of the
// configurations that missed it, and reports whether there is anything to name.
//
// Any one of those configurations loses the module, so what excludes it is their
// disjunction, and what it depends on is that disjunction being false. The
// expression is negated whole: a tag common to all of them is not the answer,
// since "integration && core" loses the module only when both are set, and
// negating each tag separately would claim it needs neither -- a stronger and
// false statement. Nor are the tags satisfying each enough, since a predicate is
// satisfied minimally by one of its branches and the others would be dropped.
//
// A configuration another already implies is dropped, since a disjunction absorbs
// it: whenever "integration && core" holds so does "integration", so the pair
// reduces to "integration" and the column says the short true thing rather than
// the long one.
func excludedBy(filters []tagFilter, reached []string) (string, bool) {
	var missed []tagFilter
	for _, f := range filters {
		if slices.Contains(reached, f.String()) {
			continue
		}
		if f.expr == nil {
			// A configuration setting no tags cannot be what excludes the module.
			return "", false
		}
		missed = append(missed, f)
	}
	if len(missed) == 0 {
		return "", false
	}

	var terms []string
	for i, f := range missed {
		if absorbed(missed, i) {
			continue
		}
		terms = append(terms, group(f.text))
	}
	return "!" + group(strings.Join(terms, " || ")), true
}

// absorbed reports whether the configuration at i says nothing the others do not,
// so that dropping it from their disjunction leaves the same predicate.
//
// A configuration is absorbed when another implies it. Two that imply each other
// are the same predicate twice, and the earlier one is kept so that exactly one
// survives.
func absorbed(missed []tagFilter, i int) bool {
	for j, other := range missed {
		if i == j || !implies(missed[i], other) {
			continue
		}
		if implies(other, missed[i]) && j > i {
			// Equivalent, and this one came first.
			continue
		}
		return true
	}
	return false
}

// implies reports whether every way of satisfying a makes b true, so that a
// disjunction holding a and b says no more than one holding b alone.
//
// The atoms are few -- a handful per configuration -- so every assignment over
// their union is tried rather than reasoned about.
func implies(a, b tagFilter) bool {
	atoms := tagSet{}
	collect(a.expr, atoms)
	collect(b.expr, atoms)
	names := slices.Sorted(maps.Keys(atoms))

	for mask := range 1 << len(names) {
		on := tagSet{}
		for i, name := range names {
			if mask&(1<<i) != 0 {
				on.add(name)
			}
		}
		if a.expr.Eval(on.isSet) && !b.expr.Eval(on.isSet) {
			return false
		}
	}
	return true
}

// group parenthesises an expression when it is not already a single term, so that
// negating or joining it cannot rebind the operators.
func group(text string) string {
	if !strings.ContainsAny(text, " ()") {
		return text
	}
	if strings.HasPrefix(text, "(") && strings.HasSuffix(text, ")") {
		return text
	}
	return "(" + text + ")"
}

// annotate records against each module the configurations that reach it, leaving
// a module no build reaches unmarked.
//
// A module reached whatever is set is unconditional, and a capped listing says so
// with "*" alone rather than spending the width on every configuration that was
// swept. An unlimited one names them, as it writes versions in full.
func (s *tagSpread) annotate(modules []module.Module) {
	for i := range modules {
		names := s.reached[modules[i].Name]
		if len(names) == 0 {
			continue
		}
		if _, ok := s.conditional[modules[i].Name]; !ok && !module.Wide {
			modules[i].Tags = []string{defaultTagSet}
			continue
		}
		modules[i].Tags = order(names)
	}
	log.WithFields(log.Fields{
		"modules": len(modules),
		"reached": len(s.reached),
	}).Debug("Recorded which configurations reach each module across the workspace")
}

// order renders the configurations for a listing, the plain build first and the
// rest sorted.
//
// The plain build leads because a row reads as what the module needs before what
// it excludes: "* !integration" says it is in the plain build and lost when the
// tag is set. Sorting alone would put "!integration" first, since "!" precedes
// "*".
func order(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	if _, ok := names[defaultTagSet]; ok {
		out = append(out, defaultTagSet)
	}
	rest := slices.Sorted(maps.Keys(names))
	return append(out, slices.DeleteFunc(rest, func(name string) bool {
		return name == defaultTagSet
	})...)
}

// setsTags reports whether a configuration asks for any tag to be set, which is
// what makes naming it actionable.
func setsTags(name string) bool { return name != defaultTagSet }

// filterNames renders the configurations for a log line.
func filterNames(filters []tagFilter) string {
	names := make([]string, 0, len(filters))
	for _, f := range filters {
		names = append(names, f.String())
	}
	return strings.Join(slices.Sorted(slices.Values(names)), ", ")
}
