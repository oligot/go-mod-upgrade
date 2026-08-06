package module

import (
	"fmt"
	"slices"
	"strings"
)

// The keys accepted by the --labels flag. They name the same properties as the
// --sort and --columns keys, so the three flags read alike: --sort orders a listing,
// --columns decides what each row shows, and --labels which rows it has.
const (
	// FilterCVE keeps the modules carrying an advisory.
	FilterCVE = "cve"
	// FilterDelta keeps the modules with a newer version available, and the ones where
	// that could not be established: an unchecked module might have an upgrade waiting,
	// and dropping it would report an unexamined tree as a clean one.
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
	// FilterCooldown keeps the releases still settling, which are withheld unless
	// asked for.
	FilterCooldown = "cooldown"
	// FilterStepped keeps the modules offered an earlier version than the newest
	// published, because the newest has not settled and the module is still releasing.
	FilterStepped = "stepped"
	// FilterDeprecated, FilterRetracted and FilterArchived keep the modules given up
	// on in one particular way. FilterDisowned is the union of the three, which is
	// usually what a reader wants; these name which way, so the key a row's letter
	// stands for can select exactly that row.
	FilterDeprecated = "deprecated"
	FilterRetracted  = "retracted"
	FilterArchived   = "archived"
	// FilterUnchecked keeps the modules no proxy could be asked about, so what is
	// available is unknown rather than absent.
	FilterUnchecked = "unchecked"
	// FilterAll keeps everything, which is what a policy is generated from.
	FilterAll = "all"
)

// DefaultFilters keeps the modules with an upgrade available, which is what the
// tool has always listed. It is what a signed value adjusts.
func DefaultFilters() []string {
	return []string{FilterDelta}
}

// filters maps each key to what it keeps.
//
// The keys naming a label take their predicate from labelSpecs, so selecting on a
// key and printing its letter are decided by one function: a row marked "V" is
// exactly a row --labels=+cve keeps. The rest are keys with no letter -- they select
// rows without marking them, there being nothing about a module to abbreviate.
var filters = func() map[string]func(Module) bool {
	all := map[string]func(Module) bool{
		FilterDelta:    func(m Module) bool { return m.Unchecked || !m.From.Equal(m.To) },
		FilterDirect:   func(m Module) bool { return !m.Indirect },
		FilterDisowned: func(m Module) bool { return m.Disowned() },
		FilterAll:      func(Module) bool { return true },
	}
	for _, spec := range labelSpecs {
		all[spec.key] = spec.holds
	}
	return all
}()

// FilterKeys lists the accepted keys, for help text and error messages.
//
// The keys naming a label come first, in the order a row prints their letters, so the
// list reads as the label column does. Then the keys selecting without marking.
func FilterKeys() []string {
	keys := LabelKeys()
	return append(keys, FilterDelta, FilterDirect, FilterDisowned, FilterAll)
}

// Filter decides which modules a listing contains.
type Filter struct {
	// Keys names the chain as given, for reporting.
	Keys []string

	keep []func(Module) bool
	drop []func(Module) bool
}

// Wants reports whether a key was asked for, so a caller gating something outside
// the listing agrees with what the listing shows.
func (s Filter) Wants(key string) bool { return slices.Contains(s.Keys, key) }

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
	// A release still settling is not recommended, so it is withheld unless the
	// caller named the key. Listing it anyway would put the reader back to deciding
	// for themselves which rows are safe, which is the work this does for them.
	//
	// Checked before the drop and keep lists rather than joining them: it is a
	// default rather than something asked for, and a keep cannot override a drop.
	if mod.Cooling() && !slices.Contains(s.Keys, FilterCooldown) {
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

// UnknownFilterError reports a --labels key naming no label.
type UnknownFilterError struct {
	Key string
}

func (e *UnknownFilterError) Error() string {
	return fmt.Sprintf("unknown label %q, expected one of: %s",
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
