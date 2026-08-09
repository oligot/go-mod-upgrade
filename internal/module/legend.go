package module

import (
	"fmt"
	"strings"
)

// used collects the label letters the modules carry.
//
// Shared by both spellings of the legend so that each explains exactly what the
// listing shows, rather than deciding for itself.
func used(modules []Module) map[string]struct{} {
	seen := map[string]struct{}{}
	for i := range modules {
		for _, l := range modules[i].labels() {
			seen[l.letter] = struct{}{}
		}
	}
	return seen
}

// Legend names the labels the modules carry, briefly.
//
// A reader meeting "iD" has to guess what the letters mean. Explaining the ones no
// row uses would be noise in the same breath, so the legend is built from what the
// listing actually shows -- by asking the modules for their labels rather than by
// keeping a second list in step with them.
//
// Each letter is given with the --labels key that selects it, rather than with a
// description: the key is the shorter of the two and it is the one a reader can act
// on, since seeing why a row is listed and asking for only those rows are the same
// question. LegendLines says what the keys mean.
//
// Empty when no module carries a label, which is what keeps a legend out of a listing
// that needs none.
func Legend(modules []Module) string {
	have := used(modules)
	if len(have) == 0 {
		return ""
	}
	var parts []string
	for _, spec := range labelSpecs {
		if _, ok := have[spec.letter]; !ok {
			continue
		}
		// The letter takes the colour it has in a row, so the legend and the column
		// are read as the same thing.
		parts = append(parts, fmt.Sprintf("%s %s", paint(spec.role)(spec.letter), spec.key))
	}
	return strings.Join(parts, ", ")
}

// LegendLines explains the same labels at length, one entry per line.
//
// Each is the letter, the key that selects it, and what it means. Separate lines
// rather than one joined sentence because several of the descriptions contain a comma
// themselves, so a comma cannot also separate the entries: "indirect, reached only
// through another module" beside another entry gives no clue where one ends.
//
// Empty when no module carries a label, as Legend is.
func LegendLines(modules []Module) []string {
	have := used(modules)
	if len(have) == 0 {
		return nil
	}
	var lines []string
	for _, spec := range labelSpecs {
		if _, ok := have[spec.letter]; !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s\t%s: %s",
			paint(spec.role)(spec.letter), spec.key, spec.says))
	}
	return lines
}
