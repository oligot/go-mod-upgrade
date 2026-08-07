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
	// FilterVulnReachable keeps the modules whose vulnerable code this project
	// reaches, which is the set worth acting on first.
	FilterVulnReachable = "vuln_reachable"
	// FilterVulnPresent keeps the modules carrying an advisory this project does
	// not reach. Reachability is analysis rather than fact, so what it does not
	// call is still worth listing -- separately, since it is not the same claim.
	//
	// Disjoint from FilterVulnReachable rather than a superset of it, so that the
	// two letters a row can print are mutually exclusive and every advisory falls
	// under exactly one key. Both together are every advisory there is.
	FilterVulnPresent = "vuln_present"
	// FilterVuln is how a reader usually says FilterVulnReachable, the reached
	// advisories being the ones needing action.
	FilterVuln = "vuln"
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

// DefaultFilters keeps the modules with an upgrade available and the ones whose
// vulnerable code this project reaches. It is what a signed value adjusts.
//
// A reached advisory is listed whether or not an upgrade would resolve it, because
// a listing that withheld it would report a vulnerable tree as a clean one. That
// costs a scan on every default run, which the demand set turns into the reason the
// scan happens rather than a cost paid beside it.
//
// The resolved key rather than FilterVuln: a base is not parsed, so an alias here
// would reach filters as a key it has no predicate for, and would name no entry in
// what maps a key to the work answering it.
func DefaultFilters() []string {
	return []string{FilterVulnReachable, FilterDelta}
}

// filters maps each key to what it keeps.
//
// The keys naming a label take their predicate from labelSpecs, so selecting on a
// key and printing its letter are decided by one function: a row marked "V" is
// exactly a row --labels=+vuln keeps. The rest are keys with no letter -- they select
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

// filterAliases names the keys that stand for another.
//
// "vuln" is the short way to ask the question a reader usually means. It resolves
// rather than being a key of its own, so it cannot drift from what it abbreviates
// and cannot appear twice in a chain that wrote both spellings.
var filterAliases = map[string]string{
	FilterVuln: FilterVulnReachable,
}

// resolveFilterKey returns the key an accepted spelling names.
func resolveFilterKey(key string) string {
	if to, ok := filterAliases[key]; ok {
		return to
	}
	return key
}

// FilterKeys lists the accepted keys, for help text and error messages.
//
// The keys naming a label come first, in the order a row prints their letters, so the
// list reads as the label column does. Then the keys selecting without marking.
func FilterKeys() []string {
	keys := LabelKeys()
	return append(keys, FilterDelta, FilterDirect, FilterDisowned, FilterAll)
}

// Filter decides which modules a listing contains.
//
// A set built from a map beside the order it was accumulated in: the map decides
// membership, and orig records what the caller actually wrote. Both are needed. The
// map is what makes "was this asked for" and "does this widen discovery" one lookup
// each, and what stops a key being recorded twice -- "+vuln,+vuln" used to build three
// predicates. The slice is what lets a report say the chain back in the order it was
// given, which the map cannot recover and label order would only replace with a
// different chain's spelling.
type Filter struct {
	// orig names the keys in the order the chain accumulated them, base first.
	// Every entry is a key of asked, and no key appears twice.
	orig []string
	// asked maps each key to whether it keeps rows or excludes them. The predicate
	// is not stored: it is always filters[key], so a copy could only disagree.
	asked map[string]sense
}

// sense is what a key does to the rows it matches.
type sense int

const (
	// senseKeep lists the rows a key matches; senseDrop withholds them.
	senseKeep sense = iota
	senseDrop
)

// add records a key, keeping the first sign given for it.
//
// First rather than last so an exclusion cannot be undone by a later mention, which
// is the same precedence Keep applies: "-vuln,+vuln" and "+vuln,-vuln" agree.
func (s *Filter) add(key string, how sense) {
	if s.asked == nil {
		s.asked = make(map[string]sense)
	}
	if _, seen := s.asked[key]; seen {
		if how == senseDrop {
			s.asked[key] = senseDrop
		}
		return
	}
	s.asked[key] = how
	s.orig = append(s.orig, key)
}

// Wants reports whether a key was asked for, whichever sign it carried, so a caller
// gating something outside the listing agrees with what the listing shows.
//
// Sign-agnostic because answering the question is what both signs need: hiding the
// modules carrying an advisory still means finding out which ones do.
func (s Filter) Wants(key string) bool {
	_, ok := s.asked[key]
	return ok
}

// Keeps reports whether a key was asked to keep rows rather than to exclude them.
//
// Where Wants decides whether a question gets answered, this decides how far to look
// for rows to answer it about. Excluding a category needs no wider search than
// listing without it: the result is the same listing whether a row was discovered
// and dropped or never discovered at all.
func (s Filter) Keeps(key string) bool {
	how, ok := s.asked[key]
	return ok && how == senseKeep
}

// Keys names the chain as given, base first, for reporting.
func (s Filter) Keys() []string { return slices.Clip(s.orig) }

// Keep reports whether a module belongs in the listing.
//
// A module is kept when any of the requested properties holds, so
// "+vuln,+delta" means an advisory or an available upgrade. A negated key
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
	// Checked before the keys rather than joining them: it is a default rather than
	// something asked for, and a keep cannot override a drop.
	if mod.Cooling() && !s.Wants(FilterCooldown) {
		return false
	}
	// Walked in the order given so a predicate runs in a fixed order, and every
	// exclusion is checked first: a drop outranks a keep however the chain ordered
	// them.
	for _, key := range s.orig {
		if s.asked[key] == senseDrop && filters[key](mod) {
			return false
		}
	}
	kept := false
	for _, key := range s.orig {
		if s.asked[key] != senseKeep {
			continue
		}
		kept = true
		if filters[key](mod) {
			return true
		}
	}
	// A chain of nothing but exclusions keeps whatever it did not drop.
	return !kept
}

// ParseFilter reads a comma-separated chain of keys and returns what a listing
// keeps, starting from base.
//
// An unsigned list names the set outright, so "vuln" keeps the modules carrying an
// advisory and nothing else. A signed key adjusts base instead: "+vuln" keeps what
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
			f.add(key, senseKeep)
		}
		return f, nil
	}

	type change struct {
		key string
		how sense
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
		signed, how := false, senseKeep
		switch field[0] {
		case '-':
			signed, how = true, senseDrop
			field = field[1:]
		case '+':
			signed = true
			field = field[1:]
		}
		key := strings.ToLower(strings.TrimSpace(field))
		if _, ok := filters[key]; !ok {
			if _, alias := filterAliases[key]; !alias {
				return Filter{}, &UnknownFilterError{Key: key}
			}
		}
		key = resolveFilterKey(key)
		if signed {
			changes = append(changes, change{key, how})
			continue
		}
		named = append(named, key)
	}

	if len(named) > 0 && len(changes) > 0 {
		return Filter{}, fmt.Errorf(
			"filter %q mixes naming a set with adjusting one; write either a plain list or only signed keys", spec)
	}

	var f Filter
	if len(named) > 0 {
		for _, key := range named {
			f.add(key, senseKeep)
		}
		return f, nil
	}
	for _, key := range base {
		f.add(key, senseKeep)
	}
	for _, ch := range changes {
		f.add(ch.key, ch.how)
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
