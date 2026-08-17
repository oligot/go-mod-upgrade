package module

import "slices"

// Modules is a result set: every module a run gathered, one row each.
//
// A run is a pipeline -- gather, filter, sort, display -- and each stage takes the
// whole set and returns it. Naming the set is what lets a stage read as what it
// does, so the order they run in is legible at the one place they are chained
// rather than spread across the writers.
//
// A row is atomic. Where a workspace's members require different versions of a
// module, Split makes that several rows rather than one row carrying a list, so a
// filter selects and a sort orders the rows a reader is shown. Combining them again
// is Coalesce, which the formats wanting one line per module call last.
type Modules []Module

// Filter returns the rows the chain selects, in the order given.
func (ms Modules) Filter(show Filter) Modules {
	kept := make(Modules, 0, len(ms))
	for _, mod := range ms {
		if show.Keep(mod) {
			kept = append(kept, mod)
		}
	}
	return slices.Clip(kept)
}

// SortBy orders the rows by the chain, keeping the order of those it cannot
// distinguish.
//
// Stable because the rows of one module arrive in the order their requirements were
// read, and a chain saying nothing about what separates them should not shuffle
// them.
func (ms Modules) SortBy(by Sort) Modules {
	slices.SortStableFunc(ms, by.Compare)
	return ms
}

// Split returns one row per version the members of a workspace require.
func (ms Modules) Split() Modules { return PerRequirement(ms) }

// PerConfiguration returns one row per configuration reaching a module.
func (ms Modules) PerConfiguration() Modules { return PerConfiguration(ms) }

// Coalesce returns one row per module, combining the rows Split made.
func (ms Modules) Coalesce() Modules { return Coalesce(ms) }

// ByName groups the rows by the module they belong to.
//
// The rows of one module need not arrive together: a sort orders the whole set by
// what a reader asked for, and the name is only the last thing it compares.
func (ms Modules) ByName() map[string]Modules {
	out := map[string]Modules{}
	for _, mod := range ms {
		out[mod.Name] = append(out[mod.Name], mod)
	}
	return out
}
