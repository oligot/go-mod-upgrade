package module

import (
	"fmt"
	"strings"
)

// Legend explains the labels the modules carry, and nothing else.
//
// A reader meeting "iD" has to guess what the letters mean. Explaining the ones no
// row uses would be noise in the same breath, so the legend is built from what the
// listing actually shows -- by asking the modules for their labels rather than by
// keeping a second list in step with them.
//
// Each letter is explained alongside the key that selects it, so a reader who can see
// why a row is listed can also ask for only those rows.
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
	for _, spec := range labelSpecs {
		if _, ok := used[spec.letter]; !ok {
			continue
		}
		// The letter takes the colour it has in a row, so the legend and the column
		// are read as the same thing.
		parts = append(parts, fmt.Sprintf("%s %s", paint(spec.role)(spec.letter), spec.says))
	}
	return strings.Join(parts, ", ")
}
