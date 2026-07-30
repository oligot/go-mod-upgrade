package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/apex/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// tagArgs returns the -tags argument for a configuration, or nothing for the
// default one. A bare "-tags=" is not the same as omitting it, so the empty case
// passes no flag at all.
func (f tagFilter) tagArgs() []string {
	tags, ok := f.satisfy()
	if !ok || len(tags) == 0 {
		return nil
	}
	return []string{"-tags=" + strings.Join(tags, ",")}
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

// filterNames renders the configurations for a log line.
func filterNames(filters []tagFilter) string {
	names := make([]string, 0, len(filters))
	for _, f := range filters {
		names = append(names, f.String())
	}
	return strings.Join(slices.Sorted(slices.Values(names)), ", ")
}
