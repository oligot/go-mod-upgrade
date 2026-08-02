package module

import (
	"fmt"
	"strings"
)

// meanings says what each label letter reports, in the order a row prints them.
//
// Keyed by letter and ordered by the same slice, so the legend and a row cannot
// disagree about either.
var meanings = []struct {
	letter string
	role   string
	says   string
}{
	{fixLabel, RoleFixes, "resolves an advisory in another module"},
	{indirectLabel, RoleIndirect, "indirect, reached only through another module"},
	{cooldownLabel, RoleCooldown, "released too recently to recommend yet"},
	{transitiveLabel, RoleTransitive, "another upgrade already resolves its advisories"},
	{deprecatedLabel, RoleDeprecated, "deprecated by its author"},
	{retractedLabel, RoleRetracted, "the version in use was withdrawn"},
	{archivedLabel, RoleArchived, "asserted abandoned by a policy"},
}

// Legend explains the labels the modules carry, and nothing else.
//
// A reader meeting "iD" has to guess what the letters mean. Explaining the ones no
// row uses would be noise in the same breath, so the legend is built from what the
// listing actually shows -- by asking the modules for their labels rather than by
// keeping a second list in step with them.
//
// Empty when no module carries a label, which is what keeps a legend out of a
// listing that needs none.
func Legend(modules []Module) string {
	used := map[string]struct{}{}
	for i := range modules {
		for _, l := range modules[i].labels() {
			used[l.letter] = struct{}{}
		}
	}
	if len(used) == 0 {
		return ""
	}

	var parts []string
	for _, m := range meanings {
		if _, ok := used[m.letter]; !ok {
			continue
		}
		// The letter takes the colour it has in a row, so the legend and the column
		// are read as the same thing.
		parts = append(parts, fmt.Sprintf("%s %s", paint(m.role)(m.letter), m.says))
	}
	return strings.Join(parts, ", ")
}
