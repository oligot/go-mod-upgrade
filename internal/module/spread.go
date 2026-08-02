package module

// PerConfiguration returns one row per configuration reaching a module, so that a
// module in the build under several is listed once for each.
//
// A listing has one line per row, and a module reached three ways would otherwise
// crowd three configurations into one cell. One row each answers the question a
// reader is actually asking -- which upgrade belongs to which build -- and leaves
// them to collapse the rows by eye, the sort having placed them together.
//
// A row carries everything the module did. None of it was gathered per
// configuration: what each sweep found is unioned before a module is annotated, so
// an advisory belongs to the module rather than to one of its rows, and dropping it
// from the others would read as though one build alone carried it.
//
// A module naming no configuration stays one row. Either every build reaches it or
// none does, and there is nothing to split.
func PerConfiguration(modules []Module) []Module {
	out := make([]Module, 0, len(modules))
	for _, mod := range modules {
		if len(mod.Tags) <= 1 {
			out = append(out, mod)
			continue
		}
		for _, name := range mod.Tags {
			row := mod
			row.Tags = []string{name}
			out = append(out, row)
		}
	}
	return out
}
