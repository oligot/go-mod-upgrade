package module

import (
	"fmt"
	"slices"
	"strings"
)

// The keys accepted by the --show flag. They name the same properties as the
// --sort keys, so the two flags read alike: --sort orders a listing and --show
// decides what is in it.
const (
	// FilterCVE keeps the modules carrying an advisory.
	FilterCVE = "cve"
	// FilterDelta keeps the modules with a newer version available.
	FilterDelta = "delta"
	// FilterDirect and FilterIndirect keep the modules by how they are required.
	FilterDirect   = "direct"
	FilterIndirect = "indirect"
	// FilterDisowned keeps the modules given up on, whether by their author or by
	// a reviewer. It covers all three, since what a reader usually wants is
	// every module that has been abandoned rather than one flavour of it.
	FilterDisowned = "disowned"
	// FilterTransitive keeps the modules another upgrade would resolve, which is
	// most useful negated: "+all,-transitive" is everything needing action.
	FilterTransitive = "transitive"
	// FilterFixes keeps the upgrades that would resolve an advisory elsewhere,
	// which is the shortest list of things worth doing.
	FilterFixes = "fixes"
	// FilterAll keeps everything, which is what a policy is generated from.
	FilterAll = "all"
)

// DefaultFilters keeps the modules with an upgrade available, which is what the
// tool has always listed. It is what a signed value adjusts.
func DefaultFilters() []string {
	return []string{FilterDelta}
}

// filters maps each key to what it keeps.
var filters = map[string]func(Module) bool{
	FilterCVE:        func(m Module) bool { return len(m.Vulns) > 0 },
	FilterDelta:      func(m Module) bool { return !m.From.Equal(m.To) },
	FilterDirect:     func(m Module) bool { return !m.Indirect },
	FilterIndirect:   func(m Module) bool { return m.Indirect },
	FilterDisowned:   func(m Module) bool { return m.Disowned() },
	FilterTransitive: func(m Module) bool { return m.IsTransitive() },
	FilterFixes:      func(m Module) bool { return m.IsFix() },
	FilterAll:        func(Module) bool { return true },
}

// FilterKeys lists the accepted keys, for help text and error messages.
func FilterKeys() []string {
	return []string{
		FilterCVE, FilterDelta, FilterDirect, FilterIndirect, FilterDisowned,
		FilterTransitive, FilterFixes, FilterAll,
	}
}

// Filter decides which modules a listing contains.
type Filter struct {
	// Keys names the chain as given, for reporting.
	Keys []string

	keep []func(Module) bool
	drop []func(Module) bool
}

// Keep reports whether a module belongs in the listing.
//
// A module is kept when any of the requested properties holds, so
// "+cve,+delta" means an advisory or an available upgrade. A negated key
// excludes regardless, so "+all,-indirect" is everything a project requires
// directly.
func (s Filter) Keep(mod Module) bool {
	// A module withheld by --ignore is never listed, whatever was asked for.
	// It is still checked against a policy, which happens before this.
	if mod.Ignored {
		return false
	}
	for _, drop := range s.drop {
		if drop(mod) {
			return false
		}
	}
	if len(s.keep) == 0 {
		return true
	}
	for _, keep := range s.keep {
		if keep(mod) {
			return true
		}
	}
	return false
}

// ParseFilter reads a comma-separated chain of keys and returns what a listing
// keeps, starting from base.
//
// An unsigned list names the set outright, so "cve" keeps the modules carrying an
// advisory and nothing else. A signed key adjusts base instead: "+cve" keeps what
// base keeps and those as well, and "-indirect" keeps base less those. Mixing the
// two forms is refused rather than guessed at, as --columns refuses it.
//
// Adjusting is what makes "the usual, plus these" expressible. Without it every
// value would replace the default, so naming one property would silently discard
// the rest.
func ParseFilter(spec string, base []string) (Filter, error) {
	if strings.TrimSpace(spec) == "" {
		var f Filter
		for _, key := range base {
			f.Keys = append(f.Keys, key)
			f.keep = append(f.keep, filters[key])
		}
		return f, nil
	}

	type change struct {
		key     string
		exclude bool
	}
	var (
		named   []string
		changes []change
	)
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		signed, exclude := false, false
		switch field[0] {
		case '-':
			signed, exclude = true, true
			field = field[1:]
		case '+':
			signed = true
			field = field[1:]
		}
		key := strings.ToLower(strings.TrimSpace(field))
		if _, ok := filters[key]; !ok {
			return Filter{}, &UnknownFilterError{Key: key}
		}
		if signed {
			changes = append(changes, change{key, exclude})
			continue
		}
		named = append(named, key)
	}

	if len(named) > 0 && len(changes) > 0 {
		return Filter{}, fmt.Errorf(
			"filter %q mixes naming a set with adjusting one; write either a plain list or only signed keys", spec)
	}

	var f Filter
	add := func(key string, exclude bool) {
		f.Keys = append(f.Keys, key)
		if exclude {
			f.drop = append(f.drop, filters[key])
			return
		}
		f.keep = append(f.keep, filters[key])
	}
	if len(named) > 0 {
		for _, key := range named {
			add(key, false)
		}
		return f, nil
	}
	for _, key := range base {
		add(key, false)
	}
	for _, ch := range changes {
		add(ch.key, ch.exclude)
	}
	return f, nil
}

// UnknownFilterError reports a --show key with no filter.
type UnknownFilterError struct {
	Key string
}

func (e *UnknownFilterError) Error() string {
	return fmt.Sprintf("unknown show key %q, expected one of: %s",
		e.Key, strings.Join(FilterKeys(), ", "))
}

// Apply returns the modules a listing should contain, in the order given.
func Apply(modules []Module, show Filter) []Module {
	kept := make([]Module, 0, len(modules))
	for _, mod := range modules {
		if show.Keep(mod) {
			kept = append(kept, mod)
		}
	}
	return slices.Clip(kept)
}
