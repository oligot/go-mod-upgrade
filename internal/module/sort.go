package module

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Comparator orders two modules for display.
// It follows the cmp.Compare convention: a negative result means a sorts
// before b, a positive result means it sorts after.
type Comparator func(a, b Module) int

// The keys accepted by the --sort flag.
const (
	// SortVuln puts modules carrying an advisory first, reachable ones ahead of
	// those merely present.
	SortVuln = "vuln"
	// SortName orders by module path.
	SortName = "name"
	// SortMajor, SortMinor, SortMicro and SortPrerelease order by how far the
	// respective part of the version moves.
	SortMajor      = "major"
	SortMinor      = "minor"
	SortMicro      = "micro"
	SortPrerelease = "prerelease"
	// SortDelta orders by the size of the version change as a whole.
	SortDelta = "delta"
	// SortDeps orders by how much of the build depends on the module.
	SortDeps = "deps"
	// SortDirect puts the modules imported directly ahead of those reached
	// only through another.
	SortDirect = "direct"
	// SortDisowned puts the modules given up on first, whether by their author
	// or by a policy.
	SortDisowned = "disowned"
	// SortTransitive puts the modules another upgrade would resolve last, since
	// they need no direct action.
	SortTransitive = "transitive"
	// SortFixes leads with the upgrades that would resolve an advisory in another
	// module, since taking one clears a finding elsewhere.
	SortFixes = "fixes"
	// SortTags orders a module's rows by the configuration each stands for, which
	// is what tells apart two rows naming one module.
	SortTags = "tags"
	// SortCooldown puts the releases still settling last, since they are not
	// recommended yet.
	SortCooldown = "cooldown"
)

// DefaultSorts is the chain used when --sort is not given, and what a signed value
// adds to. It reads as a priority list, most actionable first.
//
// An upgrade that resolves an advisory in another module leads, since taking it
// clears a finding rather than merely moving a version, and the one clearing the
// most leads within that. Then the advisories needing direct action, then what
// the code imports directly. Being handled by another upgrade demotes a module
// below all of those, since it needs nothing done. How disruptive the change is
// settles the rest, with the name settling anything still equal.
func DefaultSorts() []string {
	return []string{
		SortFixes, SortVuln, SortCooldown, SortDirect, SortTransitive, SortDelta,
		SortName,
	}
}

// comparators maps each key to its implementation. Each orders the more
// pressing module first, so a leading "+" is the natural direction and "-"
// reverses it.
var comparators = map[string]Comparator{
	SortVuln:       byVuln,
	SortName:       ByName,
	SortMajor:      byMajor,
	SortMinor:      byMinor,
	SortMicro:      byMicro,
	SortPrerelease: byPrerelease,
	SortDelta:      byDelta,
	SortDeps:       byDependents,
	SortDirect:     byDirect,
	SortDisowned:   byDisowned,
	SortTransitive: byTransitive,
	SortFixes:      byFixes,
	SortTags:       byTags,
	SortCooldown:   byCooldown,
}

// aliases names the keys that stand for another.
var aliases = map[string]string{
	// The flag used to take a single "risk" value, which meant the same thing.
	"risk": SortDelta,
}

// SortKeys lists the accepted keys in a stable order, for help text and error
// messages.
func SortKeys() []string {
	return []string{
		SortVuln, SortName, SortMajor, SortMinor, SortMicro,
		SortPrerelease, SortDelta, SortDeps, SortDirect, SortDisowned,
		SortTransitive, SortFixes, SortTags, SortCooldown,
	}
}

// ByName orders modules by path, ignoring case. Go tools sort module paths
// by byte value, which puts every capitalised path ahead of the lowercase
// ones, so "Masterminds" lands nowhere near "mattn". Comparing without case
// keeps related paths together, which is how the list is read.
func ByName(a, b Module) int {
	if c := cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
		return c
	}
	// Paths differing only by case still need a stable relative order.
	return cmp.Compare(a.Name, b.Name)
}

// byVuln orders modules by how much attention their advisories demand.
//
// What matters is how many advisories the code actually reaches, since those
// are the ones that can bite. Advisories that are merely present are a smell
// worth seeing rather than something to act on, so they only break ties.
func byVuln(a, b Module) int {
	if c := cmp.Compare(b.Reachable, a.Reachable); c != 0 {
		return c
	}
	return cmp.Compare(len(b.Vulns), len(a.Vulns))
}

// byMajor, byMinor, byMicro order by how far that part of the version moves,
// the largest jump first. The distance is compared rather than the fact of a
// change, so that 0.4 -> 0.40 is not presented as being as small as
// 0.1.14 -> 0.1.15.
func byMajor(a, b Module) int {
	return cmp.Compare(distance(b.From.Major(), b.To.Major()), distance(a.From.Major(), a.To.Major()))
}

func byMinor(a, b Module) int {
	return cmp.Compare(distance(b.From.Minor(), b.To.Minor()), distance(a.From.Minor(), a.To.Minor()))
}

func byMicro(a, b Module) int {
	return cmp.Compare(distance(b.From.Patch(), b.To.Patch()), distance(a.From.Patch(), a.To.Patch()))
}

// byPrerelease puts a change of prerelease ahead of none, since leaving or
// entering a prerelease says more than the version numbers alone.
func byPrerelease(a, b Module) int {
	return cmp.Compare(changed(b), changed(a))
}

// tier ranks a change by which part of the version moves, lower being more
// disruptive. What moved matters more than how far: a new major discards every
// guarantee the old version made, however small the number.
type tier int

const (
	tierMajor tier = iota
	tierMinor
	tierMicro
	tierPrerelease
	tierNone
)

// classify reports which part of a version moves.
func classify(mod Module) tier {
	from, to := mod.From, mod.To
	switch {
	case from.Major() != to.Major():
		return tierMajor
	case from.Minor() != to.Minor():
		return tierMinor
	case from.Patch() != to.Patch():
		return tierMicro
	case from.Prerelease() != to.Prerelease():
		return tierPrerelease
	default:
		return tierNone
	}
}

// byDelta orders by how disruptive the upgrade is: first by which part of the
// version moves, then by how far it moves within that.
//
// Comparing the kind before the distance is what keeps a new major ahead of a
// minor that happens to jump further, while still separating 0.4 -> 0.40 from
// 0.4 -> 0.5.
func byDelta(a, b Module) int {
	ta, tb := classify(a), classify(b)
	if c := cmp.Compare(ta, tb); c != 0 {
		return c
	}
	switch ta {
	case tierMajor:
		return byMajor(a, b)
	case tierMinor:
		return byMinor(a, b)
	case tierMicro:
		return byMicro(a, b)
	default:
		return 0
	}
}

// changed reports whether the prerelease part moves.
func changed(mod Module) int {
	if mod.From.Prerelease() != mod.To.Prerelease() {
		return 1
	}
	return 0
}

// distance returns how far apart two parts of a version are.
func distance(from, to uint64) uint64 {
	if to < from {
		return from - to
	}
	return to - from
}

// byDependents orders modules by how much of the build depends on them,
// widest blast radius first. Modules whose dependents are unknown compare
// equal, which leaves the next key in the chain to decide.
func byDependents(a, b Module) int {
	return cmp.Compare(len(b.RequiredBy), len(a.RequiredBy))
}

// byDirect puts the modules imported directly ahead of those reached only
// through another.
func byDirect(a, b Module) int {
	if a.Indirect == b.Indirect {
		return 0
	}
	if a.Indirect {
		return 1
	}
	return -1
}

// byDisowned puts the modules given up on first, since no upgrade resolves being
// abandoned and they are the ones needing a decision rather than a bump.
func byDisowned(a, b Module) int {
	if a.Disowned() == b.Disowned() {
		return 0
	}
	if a.Disowned() {
		return -1
	}
	return 1
}

// byFixes leads with the upgrades that would resolve an advisory elsewhere, the
// ones clearing the most findings first.
//
// An upgrade fixing three modules is worth more than one fixing a single module,
// so the count decides rather than merely whether it fixes anything.
func byFixes(a, b Module) int {
	return cmp.Compare(len(b.Fixes), len(a.Fixes))
}

// byCooldown puts the releases still settling last, since they are not recommended
// yet.
//
// The second comparator whose "+" direction is inverted, as byTransitive is: both
// demote rather than promote, and a leading "+" reads as "demote these" rather than
// "lead with these".
//
// Ordered among themselves by when they were published, freshest last, so a reader
// scanning down sees the ones closest to being ready first.
func byCooldown(a, b Module) int {
	if a.Cooling() != b.Cooling() {
		if a.Cooling() {
			return 1
		}
		return -1
	}
	if !a.Cooling() {
		return 0
	}
	return a.Released.Compare(b.Released)
}

// byTags orders a module's rows by the configurations each stands for.
//
// It exists to decide between two rows naming one module, which the name cannot:
// a module in the build under two configurations is two rows, and without this
// their order is whatever the sweep produced. Configurations are compared as the
// text a listing shows, since that is all a row carries by the time it is sorted.
func byTags(a, b Module) int {
	return slices.Compare(a.Tags, b.Tags)
}

// byTransitive puts the modules another upgrade would resolve last, which is the
// opposite direction from every other key here: a leading "+" leads with what is
// most pressing, and a module needing no action is the least pressing thing in a
// listing.
func byTransitive(a, b Module) int {
	if a.IsTransitive() == b.IsTransitive() {
		return 0
	}
	if a.IsTransitive() {
		return 1
	}
	return -1
}

// Sort is a chain of keys, applied in turn until one of them decides.
type Sort struct {
	// Keys names the chain as given, for reporting which columns to show in
	// which order.
	Keys []string

	compare []Comparator
}

// Compare orders two modules by the first key that distinguishes them.
func (s Sort) Compare(a, b Module) int {
	for _, cmp := range s.compare {
		if c := cmp(a, b); c != 0 {
			return c
		}
	}
	return 0
}

// ParseSort reads a comma-separated chain of keys, each optionally signed. A
// A key may be prefixed with "-" to reverse it. A signed key extends the default
// chain rather than naming one, so "+delta" means "the usual, then by delta".
//
// The chain always ends by comparing names, so that two modules never compare
// equal and a listing does not shuffle between runs.
func ParseSort(spec string, base []string) (Sort, error) {
	var s Sort
	add := func(key string, reverse bool) error {
		if alias, ok := aliases[key]; ok {
			key = alias
		}
		c, ok := comparators[key]
		if !ok {
			return &UnknownSortError{Key: key}
		}
		if reverse {
			c = reversed(c)
		}
		s.Keys = append(s.Keys, key)
		s.compare = append(s.compare, c)
		return nil
	}

	type field struct {
		key     string
		reverse bool
	}
	var (
		named   []field
		extras  []field
		removed []string
	)
	for _, text := range strings.Split(spec, ",") {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		// The sign says which way to order, as it always has here, so a signed key
		// extends the chain rather than naming one: "-delta" reads as "and then by
		// delta, descending". Removal therefore needs a mark of its own, which is
		// "!": the sign is spoken for, and dropping one key from the default should
		// not mean writing the others out.
		signed, reverse, drop := false, false, false
		switch text[0] {
		case '!':
			drop = true
			text = text[1:]
		case '-':
			signed, reverse = true, true
			text = text[1:]
		case '+':
			signed = true
			text = text[1:]
		}
		key := strings.ToLower(strings.TrimSpace(text))
		if key == "" {
			return Sort{}, &UnknownSortError{Key: text}
		}
		if alias, ok := aliases[key]; ok {
			key = alias
		}
		if _, ok := comparators[key]; !ok {
			return Sort{}, &UnknownSortError{Key: key}
		}
		switch {
		case drop:
			removed = append(removed, key)
		case signed:
			extras = append(extras, field{key, reverse})
		default:
			named = append(named, field{key, false})
		}
	}

	if len(named) > 0 && len(removed) > 0 {
		return Sort{}, fmt.Errorf(
			"sort %q names a chain and removes from one; %q has nothing to remove from",
			spec, "!"+removed[0])
	}

	// A plain list names the chain outright; a signed or removed key adjusts the
	// default. Mixing a signed key with a named one is not refused as the other
	// selectors refuse it: a chain is ordered, so "vuln,+delta" reads naturally as
	// "by advisory, then by delta".
	if len(named) == 0 {
		for _, key := range base {
			if slices.Contains(removed, key) {
				continue
			}
			if err := add(key, false); err != nil {
				return Sort{}, err
			}
		}
	}
	for _, f := range append(named, extras...) {
		if err := add(f.key, f.reverse); err != nil {
			return Sort{}, err
		}
	}

	// Without a name comparison somewhere the order is only partial, and equal
	// modules would appear in whatever order they were discovered.
	if !slices.Contains(s.Keys, SortName) {
		s.Keys = append(s.Keys, SortName)
		s.compare = append(s.compare, ByName)
	}
	// Two rows can name one module, one per configuration reaching it, which the
	// name cannot separate. Compared after everything else, so a module's rows stay
	// together and are ordered among themselves rather than left as the sweep
	// produced them.
	//
	// Not recorded in Keys: it settles a tie the caller's chain cannot see rather
	// than answering something they asked for, and Keys is read back to report on
	// what they asked for.
	s.compare = append(s.compare, byTags)
	return s, nil
}

// reversed flips the direction of a comparator.
func reversed(c Comparator) Comparator {
	return func(a, b Module) int { return -c(a, b) }
}

// UnknownSortError reports a --sort key that has no comparator.
type UnknownSortError struct {
	Key string
}

func (e *UnknownSortError) Error() string {
	return fmt.Sprintf("unknown sort key %q, expected one of: %s",
		e.Key, strings.Join(SortKeys(), ", "))
}
