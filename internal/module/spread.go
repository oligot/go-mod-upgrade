package module

import "strings"

// PerConfiguration returns one row per configuration reaching a module, so that a
// module in the build under several is listed once for each.
//
// A listing has one line per row, and a module reached three ways would otherwise
// crowd three configurations into one cell. One row each answers the question a
// reader is actually asking -- which upgrade belongs to which build -- and leaves
// them to collapse the rows by eye, the sort having placed them together.
//
// What excludes a module is not one of those builds. "In the plain build, and lost
// once integration is set" is a single statement about a single build, so a negated
// configuration qualifies the rows rather than becoming one: split out, one row
// would claim the reach without the exclusion and the other the reverse.
//
// A row carries everything else the module did. None of it was gathered per
// configuration: what each sweep found is unioned before a module is annotated, so
// an advisory belongs to the module rather than to one of its rows, and dropping it
// from the others would read as though one build alone carried it.
//
// A module naming no configuration stays one row. Either every build reaches it or
// none does, and there is nothing to split.
func PerConfiguration(modules []Module) []Module {
	out := make([]Module, 0, len(modules))
	for _, mod := range modules {
		var reached, excluded []string
		for _, name := range mod.Tags {
			if strings.HasPrefix(name, "!") {
				excluded = append(excluded, name)
				continue
			}
			reached = append(reached, name)
		}
		if len(reached) <= 1 {
			out = append(out, mod)
			continue
		}
		for _, name := range reached {
			row := mod
			row.Tags = append([]string{name}, excluded...)
			out = append(out, row)
		}
	}
	return out
}
