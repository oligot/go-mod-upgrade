package module

import (
	"cmp"
	"strings"
)

// Comparator orders two modules for display.
// It follows the cmp.Compare convention: a negative result means a sorts
// before b, a positive result means it sorts after.
type Comparator func(a, b Module) int

// risk classifies an update by how likely it is to break a build,
// from least to most disruptive. Lower values sort first.
type risk int

const (
	riskPatch risk = iota
	riskMinor
	// riskUnstable covers modules still below v1, where the module
	// contract allows breaking changes in any release.
	riskUnstable
	riskMajor
)

// classify determines the risk tier of an update.
func classify(mod Module) risk {
	from, to := mod.From, mod.To
	switch {
	case from.Major() != to.Major():
		return riskMajor
	case from.Major() == 0:
		return riskUnstable
	case from.Minor() != to.Minor():
		return riskMinor
	default:
		return riskPatch
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

// ByRisk orders modules from safest to most disruptive, leaving major
// version bumps last. Within the sub-v1 tier the size of the jump breaks
// the tie, so that 0.4 -> 0.40 is not presented as being as safe as
// 0.1.14 -> 0.1.15.
func ByRisk(a, b Module) int {
	ra, rb := classify(a), classify(b)
	if c := cmp.Compare(ra, rb); c != 0 {
		return c
	}
	if ra == riskUnstable {
		if c := cmp.Compare(b.To.Minor()-b.From.Minor(), a.To.Minor()-a.From.Minor()); c != 0 {
			return c
		}
		if c := cmp.Compare(b.To.Patch()-b.From.Patch(), a.To.Patch()-a.From.Patch()); c != 0 {
			return c
		}
	}
	return ByName(a, b)
}

// ByDependents orders modules by how much of the build depends on them,
// widest blast radius first. Modules whose dependents are unknown compare
// equal, which leaves them ordered by name.
func ByDependents(a, b Module) int {
	if c := cmp.Compare(len(b.RequiredBy), len(a.RequiredBy)); c != 0 {
		return c
	}
	return ByName(a, b)
}

// Comparators maps the values accepted by the --sort flag to their
// implementations. DefaultSort names the value used when the flag is absent.
var Comparators = map[string]Comparator{
	"name": ByName,
	"risk": ByRisk,
	"deps": ByDependents,
}

// DefaultSort is the --sort value used when the flag is not given.
const DefaultSort = "name"

// SortNames lists the accepted --sort values in a stable order, for use in
// help text and error messages.
func SortNames() []string {
	return []string{"name", "risk", "deps"}
}

// Lookup resolves a --sort value to its Comparator.
func Lookup(name string) (Comparator, error) {
	c, ok := Comparators[name]
	if !ok {
		return nil, &UnknownSortError{Name: name}
	}
	return c, nil
}

// UnknownSortError reports a --sort value that has no comparator.
type UnknownSortError struct {
	Name string
}

func (e *UnknownSortError) Error() string {
	return "unknown sort " + e.Name + ", expected one of: " + strings.Join(SortNames(), ", ")
}
