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
	// SortCVE puts modules carrying an advisory first, reachable ones ahead of
	// those merely present.
	SortCVE = "cve"
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
)

// DefaultSort is the chain used when --sort is not given. Advisories come
// first, since an upgrade that closes one is the most pressing; then what the
// code imports directly, then how disruptive the change is, with the name
// settling anything still equal.
const DefaultSort = "+" + SortCVE + ",+" + SortDirect + ",+" + SortDelta + ",+" + SortName

// comparators maps each key to its implementation. Each orders the more
// pressing module first, so a leading "+" is the natural direction and "-"
// reverses it.
var comparators = map[string]Comparator{
	SortCVE:        byCVE,
	SortName:       ByName,
	SortMajor:      byMajor,
	SortMinor:      byMinor,
	SortMicro:      byMicro,
	SortPrerelease: byPrerelease,
	SortDelta:      byDelta,
	SortDeps:       byDependents,
	SortDirect:     byDirect,
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
		SortCVE, SortName, SortMajor, SortMinor, SortMicro,
		SortPrerelease, SortDelta, SortDeps, SortDirect,
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

// byCVE orders modules by how much attention their advisories demand.
//
// What matters is how many advisories the code actually reaches, since those
// are the ones that can bite. Advisories that are merely present are a smell
// worth seeing rather than something to act on, so they only break ties.
func byCVE(a, b Module) int {
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
// key may be prefixed with "-" to reverse it; "+" is the default and may be
// given for symmetry.
//
// The chain always ends by comparing names, so that two modules never compare
// equal and a listing does not shuffle between runs.
func ParseSort(spec string) (Sort, error) {
	if strings.TrimSpace(spec) == "" {
		spec = DefaultSort
	}

	var s Sort
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		reverse := false
		switch field[0] {
		case '-':
			reverse = true
			field = field[1:]
		case '+':
			field = field[1:]
		}
		key := strings.ToLower(field)
		if key == "" {
			return Sort{}, &UnknownSortError{Key: field}
		}

		if alias, ok := aliases[key]; ok {
			key = alias
		}
		c, ok := comparators[key]
		if !ok {
			return Sort{}, &UnknownSortError{Key: key}
		}
		if reverse {
			c = reversed(c)
		}
		s.Keys = append(s.Keys, key)
		s.compare = append(s.compare, c)
	}

	// Without a name comparison somewhere the order is only partial, and equal
	// modules would appear in whatever order they were discovered.
	if !slices.Contains(s.Keys, SortName) {
		s.Keys = append(s.Keys, SortName)
		s.compare = append(s.compare, ByName)
	}
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
