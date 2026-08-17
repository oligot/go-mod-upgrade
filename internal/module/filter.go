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
	// FilterDowngrade keeps the modules whose available version is older than the one
	// installed.
	//
	// A subset of FilterDelta rather than a sibling of it: what is available differs
	// from what is installed, which is what delta asks. The direction is what this
	// names, so "-downgrade" is how a listing asks for the upgrades alone.
	FilterDowngrade = "downgrade"
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
	// intersectSeparator joins the keys a row must carry together, where a comma
	// separates the keys any of which will do.
	intersectSeparator = "&"
)

// DefaultFilters keeps the modules with an upgrade available and the ones whose
// vulnerable code this project reaches. It is what a signed value adjusts.
//
// A reached advisory is listed whether or not an upgrade would resolve it, because
// a listing that withheld it would report a vulnerable tree as a clean one. That
// costs a scan on every default run, which the demand set turns into the reason the
// scan happens rather than a cost paid beside it.
//
// An upgrade counts whether the module is required directly or only through another.
// A project ships the version of an indirect requirement it resolves, so an upgrade
// to one is an upgrade to take, and a default that read no further reported a
// workspace whose every upgradable module was indirect as having nothing to do.
// Reading them costs a wider discovery on every run, which is the price of the
// listing being true.
//
// Intersected with delta rather than named alone, which is the whole reason the two
// can be intersected. Naming the indirect key keeps every indirect module, nearly all
// of a build list and nearly all of it already current, so the rows worth acting on
// would arrive buried in the ones that are already right.
//
// The resolved key rather than FilterVuln: a base is not parsed, so an alias here
// would reach filters as a key it has no predicate for, and would name no entry in
// what maps a key to the work answering it.
func DefaultFilters() []string {
	return []string{
		FilterVulnReachable,
		FilterDelta,
		FilterIndirect + intersectSeparator + FilterDelta,
	}
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
	// orig names the terms in the order the chain accumulated them, base first.
	// Every key of every term is a key of asked, and no term appears twice.
	orig []term
	// asked maps each key to whether it keeps rows or excludes them. The predicate
	// is not stored: it is always filters[key], so a copy could only disagree.
	//
	// Keyed by the individual key rather than by the term, since what a caller asks
	// about is a property: Wants(FilterCooldown) is the same question whether the
	// chain named cooldown alone or intersected it with something.
	asked map[string]sense
}

// term is one entry of a chain: the keys a row must carry together to match it.
//
// A single key is a term of one. Several joined with "&" match only the rows every
// one of them holds for, which is what makes "the indirect modules that have an
// upgrade" expressible -- a comma keeps the rows either property holds for, and
// there was no spelling for the rows both do.
type term struct {
	keys []string
	how  sense
}

// holds reports whether a module carries every key of the term.
//
// A key with no predicate holds for nothing rather than crashing. ParseFilter rejects
// an unknown key, so reaching here with one means a base named it, and a base is
// written in this package rather than typed by a caller: the term is a mistake in the
// source, which TestFilterKeysListsEveryFilter catches. Listing nothing is the safe
// reading of the two, a panic in a listing being worse than a row withheld.
func (t term) holds(mod Module) bool {
	for _, key := range t.keys {
		predicate, ok := filters[key]
		if !ok || !predicate(mod) {
			return false
		}
	}
	return true
}

// String spells the term as a caller would write it, for reporting.
func (t term) String() string { return strings.Join(t.keys, intersectSeparator) }

// sense is what a key does to the rows it matches.
type sense int

const (
	// senseKeep lists the rows a key matches; senseDrop withholds them.
	senseKeep sense = iota
	senseDrop
)

// add records a term, keeping the first sign given for it.
//
// First rather than last so an exclusion cannot be undone by a later mention, which
// is the same precedence Keep applies: "-vuln,+vuln" and "+vuln,-vuln" agree.
//
// Recorded twice over: the term joins the chain, and each of its keys is marked in
// asked. A caller asking whether a property was mentioned means the property, not the
// term it arrived in, so intersecting a key still answers for it.
func (s *Filter) add(keys []string, how sense) {
	if len(keys) == 0 {
		return
	}
	if s.asked == nil {
		s.asked = make(map[string]sense)
	}
	t := term{keys: keys, how: how}
	spelling := t.String()
	for i, seen := range s.orig {
		if seen.String() != spelling {
			continue
		}
		// Named again. A drop wins, matching the precedence above, and the term keeps
		// its original place in the chain.
		if how == senseDrop {
			s.orig[i].how = senseDrop
			for _, key := range keys {
				s.asked[key] = senseDrop
			}
		}
		return
	}
	s.orig = append(s.orig, t)
	for _, key := range keys {
		// A key already asked about keeps the sense it was first given, an exclusion
		// outranking a later keep as it does between terms.
		if prev, ok := s.asked[key]; ok && prev == senseDrop {
			continue
		}
		s.asked[key] = how
	}
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

// Keys names the chain as given, base first, for reporting. A term intersecting
// several keys reads as the caller wrote it.
//
// An excluded term carries its "-", since a sign is what a report cannot drop: a key
// and its negation select complementary sets of rows -- "delta" keeps the modules with
// an upgrade to take and "-delta" keeps exactly the rest -- so reporting them alike
// would name a chain the caller did not write. A keep is spelled bare rather than
// with "+", both forms selecting the same rows and the base having been written by
// this package rather than typed.
//
// This is the only way to recover what a --labels chain asked for; Columns carries
// Spec for the same purpose, and Wants and Properties answer about a property rather
// than about the chain, dropping the sign deliberately because the work that answers
// a key is the same whichever sign it carried.
//
// The sign is added here rather than by term.String, which add compares to find a term
// the chain already recorded. Signing that spelling stops "-vuln" and "+vuln" matching,
// so a chain naming both records the term twice -- the duplicate the dedup exists to
// prevent -- and reports a chain that asked for a key under both signs at once. Keep
// still refuses the rows either way, exclusions being walked first.
func (s Filter) Keys() []string {
	out := make([]string, 0, len(s.orig))
	for _, t := range s.orig {
		spelling := t.String()
		if t.how == senseDrop {
			spelling = "-" + spelling
		}
		out = append(out, spelling)
	}
	return out
}

// Properties names every key the chain mentions, whichever term it arrived in and
// whichever sign it carried.
//
// What a caller gating work outside the listing needs: intersecting a key is still
// asking about it, so the question it demands an answer to has to be asked.
func (s Filter) Properties() []string {
	out := make([]string, 0, len(s.asked))
	for _, t := range s.orig {
		for _, key := range t.keys {
			if !slices.Contains(out, key) {
				out = append(out, key)
			}
		}
	}
	return out
}

// baseKeys reads a base entry, which is one term and so may intersect several keys.
//
// The base is not parsed the way a flag value is -- it carries no signs and cannot be
// unknown, being written here rather than typed -- but it spells a term the same way,
// so the separator has one meaning wherever it appears.
func baseKeys(entry string) []string {
	var keys []string
	for _, part := range strings.Split(entry, intersectSeparator) {
		if key := strings.TrimSpace(part); key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

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
	// them. A term matches only where every one of its keys holds.
	for _, t := range s.orig {
		if t.how == senseDrop && t.holds(mod) {
			return false
		}
	}
	kept := false
	for _, t := range s.orig {
		if t.how != senseKeep {
			continue
		}
		kept = true
		if t.holds(mod) {
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
//
// Keys joined with "&" keep only the rows carrying every one of them, where a comma
// keeps the rows carrying any. A comma is the wider of the two and stays the default
// reading, so every chain written before this means what it always did. The sign
// belongs to the whole term -- "-indirect&delta" drops the rows that are both --
// since a sign inside one would be asking to intersect a property with its own
// absence.
func ParseFilter(spec string, base []string) (Filter, error) {
	if strings.TrimSpace(spec) == "" {
		var f Filter
		for _, entry := range base {
			f.add(baseKeys(entry), senseKeep)
		}
		return f, nil
	}

	type change struct {
		keys []string
		how  sense
	}
	var (
		named   [][]string
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
		// Every key of the term, each resolved and checked on its own: an unknown key
		// inside an intersection would otherwise keep nothing and look like an answer.
		var keys []string
		for _, part := range strings.Split(field, intersectSeparator) {
			key := strings.ToLower(strings.TrimSpace(part))
			if key == "" {
				continue
			}
			if _, ok := filters[key]; !ok {
				if _, alias := filterAliases[key]; !alias {
					return Filter{}, &UnknownFilterError{Key: key}
				}
			}
			key = resolveFilterKey(key)
			// An intersection naming one key twice is that key, and "vuln&vuln_reachable"
			// is one key written both ways.
			if !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		if signed {
			changes = append(changes, change{keys, how})
			continue
		}
		named = append(named, keys)
	}

	if len(named) > 0 && len(changes) > 0 {
		return Filter{}, fmt.Errorf(
			"filter %q mixes naming a set with adjusting one; write either a plain list or only signed keys", spec)
	}

	var f Filter
	if len(named) > 0 {
		for _, keys := range named {
			f.add(keys, senseKeep)
		}
		return f, nil
	}
	for _, entry := range base {
		f.add(baseKeys(entry), senseKeep)
	}
	for _, ch := range changes {
		f.add(ch.keys, ch.how)
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
