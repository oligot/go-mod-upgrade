package module

import (
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
)

// labelled returns a module carrying the label the field name suggests.
func labelled(t *testing.T, set func(*Module)) Module {
	t.Helper()
	v, err := semver.NewVersion("v1.0.0")
	if err != nil {
		t.Fatalf("parsing version: %v", err)
	}
	to, err := semver.NewVersion("v1.1.0")
	if err != nil {
		t.Fatalf("parsing version: %v", err)
	}
	m := Module{Name: "example.com/m", From: v, To: to}
	set(&m)
	return m
}

// TestLegendExplainsOnlyWhatIsUsed checks that the legend names the labels a
// listing actually carries.
//
// A reader meeting "iD" has to guess unless something says what the letters mean,
// and explaining letters no row uses would be noise in the same breath.
func TestLegendExplainsOnlyWhatIsUsed(t *testing.T) {
	indirect := labelled(t, func(m *Module) { m.Indirect = true })
	deprecated := labelled(t, func(m *Module) { m.Deprecated = "use something else" })

	got := Legend([]Module{indirect, deprecated})

	for _, want := range []string{"i", "indirect", "D", "deprecated"} {
		if !strings.Contains(got, want) {
			t.Errorf("legend %q does not explain %q", got, want)
		}
	}
	// Nothing is retracted or archived, so saying what those letters mean would
	// explain something the reader cannot see.
	for _, absent := range []string{"retracted", "archived", "resolves"} {
		if strings.Contains(got, absent) {
			t.Errorf("legend %q explains %q, which no module carries", got, absent)
		}
	}
}

// TestLegendEmptyWithoutLabels checks that a listing whose modules carry no labels
// gets no legend, since there would be nothing to explain.
func TestLegendEmptyWithoutLabels(t *testing.T) {
	plain := labelled(t, func(*Module) {})
	if got := Legend([]Module{plain}); got != "" {
		t.Errorf("legend = %q, want nothing to explain", got)
	}
}

// TestLegendOrdersAsARowDoes checks that the letters are explained in the order a
// row prints them, so a reader scanning "FiT" meets them in the same sequence.
func TestLegendOrdersAsARowDoes(t *testing.T) {
	every := labelled(t, func(m *Module) {
		m.Fixes = []string{"example.com/other"}
		m.Indirect = true
		m.FixedBy = []string{"example.com/other"}
		m.Deprecated = "gone"
		m.Retracted = []string{"withdrawn"}
		m.Archived = "abandoned"
	})

	got := Legend([]Module{every})

	// Colour escapes sit between the letter and its meaning, so compare what a
	// reader sees rather than the bytes written.
	plain := escapes.ReplaceAllString(got, "")
	var at []int
	for _, letter := range []string{"F", "i", "T", "D", "R", "A"} {
		i := strings.Index(plain, letter+" ")
		if i < 0 {
			t.Fatalf("legend %q does not explain %q", plain, letter)
		}
		at = append(at, i)
	}
	if !slices.IsSorted(at) {
		t.Errorf("legend %q explains the labels out of order", plain)
	}
}

// TestLegendTerseNamesTheKey checks that the brief legend gives each letter with the
// --labels key selecting it, rather than a description.
//
// The key is the shorter of the two and the one a reader can act on: seeing why a row
// is listed and asking for only those rows are the same question.
func TestLegendTerseNamesTheKey(t *testing.T) {
	mods := []Module{
		labelled(t, func(m *Module) { m.Indirect = true }),
		labelled(t, func(m *Module) { m.Deprecated = "use something else" }),
	}

	got := escapes.ReplaceAllString(Legend(mods), "")

	for _, want := range []string{"i " + FilterIndirect, "D " + FilterDeprecated} {
		if !strings.Contains(got, want) {
			t.Errorf("legend %q does not carry %q", got, want)
		}
	}
	// The long descriptions belong to the expanded form, which is what -LL asks for.
	if strings.Contains(got, "reached only through") {
		t.Errorf("legend %q spells out a description the terse form leaves to -LL", got)
	}
}

// TestLegendLinesExplainOnePerLine checks that the expanded legend gives one entry per
// line, each naming the letter, its key and what it means.
//
// One per line because several descriptions contain a comma themselves, so a comma
// cannot also separate the entries.
func TestLegendLinesExplainOnePerLine(t *testing.T) {
	mods := []Module{
		labelled(t, func(m *Module) { m.Indirect = true }),
		labelled(t, func(m *Module) { m.Deprecated = "use something else" }),
	}

	lines := LegendLines(mods)
	if len(lines) != 2 {
		t.Fatalf("got %d lines for two labels: %q", len(lines), lines)
	}
	for _, line := range lines {
		plain := escapes.ReplaceAllString(line, "")
		letter, rest, found := strings.Cut(plain, "\t")
		if !found {
			t.Errorf("line %q does not separate the letter from what it means", plain)
			continue
		}
		if len(letter) != 1 {
			t.Errorf("line %q does not begin with a single letter", plain)
		}
		// The key, then a colon, then the description.
		if key, says, ok := strings.Cut(rest, ": "); !ok || key == "" || says == "" {
			t.Errorf("line %q does not read as \"key: what it means\"", plain)
		}
	}
	if !strings.Contains(escapes.ReplaceAllString(lines[0], ""),
		FilterIndirect+": indirect, reached only through another module") {
		t.Errorf("line %q does not explain the indirect label in full", lines[0])
	}
}

// TestLegendLinesEmptyWithoutLabels checks that a listing needing no key gets none.
func TestLegendLinesEmptyWithoutLabels(t *testing.T) {
	if got := LegendLines([]Module{labelled(t, func(*Module) {})}); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}
