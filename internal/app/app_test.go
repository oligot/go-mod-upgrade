package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// TestPageRows covers the three bands of the --pagesize value: a share of the
// terminal, an explicit row count, and a value that means neither.
func TestPageRows(t *testing.T) {
	// Tests do not run against a terminal, so the height is the fallback of 24
	// and 19 rows are available once the prompt's own lines are reserved.
	const available = 19
	share := func(f float64) int { return int(float64(available) * f) }

	cases := []struct {
		name     string
		pageSize float64
		want     int
	}{
		{"default share", DefaultPageSize, share(DefaultPageSize)},
		{"half the screen", 0.5, available / 2},
		{"the whole screen", 1.0, available},
		{"explicit rows", 20, 20},
		{"explicit rows truncated", 20.7, 20},
		{"zero falls back", 0, share(DefaultPageSize)},
		{"negative falls back", -1, share(DefaultPageSize)},
		// A share too small to be usable still leaves enough to navigate.
		{"tiny share", 0.01, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pageRows(c.pageSize); got != c.want {
				t.Errorf("pageRows(%v) = %d, want %d", c.pageSize, got, c.want)
			}
		})
	}
}

// TestRowEmitsNoTrailingPadding pins that a row ends where its content does.
//
// Padding exists to align what comes next, so the last column on a row has
// nothing to align and is left unpadded. Trailing blanks are invisible on a
// terminal but not in a redirected listing, and trimming them afterwards would
// be treating the symptom.
func TestRowEmitsNoTrailingPadding(t *testing.T) {
	plain := mustModule(t, "example.com/plain", "v1.0.0", "v1.1.0")

	withHint := mustModule(t, "example.com/fixer", "v1.0.0", "v2.0.0")
	withHint.Fixes = []string{"example.com/vulnerable"}

	withBoth := mustModule(t, "example.com/both", "v1.0.0", "v1.1.0")
	withBoth.Fixes = []string{"example.com/vulnerable"}
	withBoth.RequiredBy = []string{"example.com/main"}

	withVulns := mustModule(t, "example.com/vulnerable", "v1.0.0", "v1.1.0")
	withVulns.Vulns = []string{"CVE-0000-0001"}

	modules := []module.Module{plain, withHint, withBoth, withVulns}
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure(modules, 0, columns, false)

	for _, mod := range modules {
		got := row(mod, l)
		if strings.HasSuffix(got, " ") {
			t.Errorf("%s: row ends with padding: %q", mod.Name, got)
		}
	}
}

// TestRowAlignsEveryColumn pins that each column starts at the same offset on
// every row, whatever the width of the content before it.
//
// The new-version column varies most: a pseudo-version is 33 characters and a
// release is 5, so leaving it unpadded shifted everything after it. That was
// visible as a hint or a required-by list wandering across the listing.
func TestRowAlignsEveryColumn(t *testing.T) {
	short := mustModule(t, "example.com/short", "v1.0.0", "v1.1.0")
	short.RequiredBy = []string{"example.com/main"}

	// A pseudo-version, far wider than a release.
	long := mustModule(t, "example.com/long",
		"v0.0.0-20220722155237-a158d28d115b", "v0.0.0-20240903120638-7835f813f4da")
	long.RequiredBy = []string{"example.com/main"}

	withHint := mustModule(t, "example.com/hinted", "v1.0.0", "v2.0.0")
	withHint.Fixes = []string{"example.com/short"}
	withHint.RequiredBy = []string{"example.com/main"}

	modules := []module.Module{short, long, withHint}
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure(modules, 0, columns, false)

	var at []int
	for _, mod := range modules {
		got := row(mod, l)
		where := strings.Index(got, "  example.com/main")
		if where < 0 {
			t.Fatalf("%s: no required-by column in %q", mod.Name, got)
		}
		at = append(at, where)
	}
	for i := range at {
		if at[i] != at[0] {
			t.Errorf("required-by starts at %v across rows, want one offset", at)
			break
		}
	}
}

// allColumns is every column, so a layout test exercises the whole row rather
// than whichever subset the flags would have implied.
func allColumns() []string { return module.ColumnNames() }

// TestRowRendersLabels pins that the labels reach a rendered row.
//
// They used to live inside the name, and moving them to a column briefly dropped
// them from the output entirely: the build passed and every test passed, because
// nothing asserted that a row contained them.
func TestRowRendersLabels(t *testing.T) {
	fixer := mustModule(t, "example.com/fixer", "v1.0.0", "v2.0.0")
	fixer.Fixes = []string{"example.com/vulnerable"}
	fixer.Indirect = true

	plain := mustModule(t, "example.com/plain", "v1.0.0", "v1.1.0")

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	modules := []module.Module{fixer, plain}
	l := measure(modules, 0, columns, false)

	got := row(fixer, l)
	if !strings.Contains(got, "Fi") {
		t.Errorf("row %q does not carry the labels", got)
	}
	// A module with none leaves the column blank rather than inventing a value.
	if bare := row(plain, l); strings.ContainsAny(bare, "FTDRA") {
		t.Errorf("row %q carries a label the module does not have", bare)
	}
}

// TestHeaderDropsTheArrow checks that the versions are separated by an arrow only
// when no heading names them. With FROM and TO above the columns the arrow is
// punctuation between two labelled fields, and it would sit oddly under TO.
func TestHeaderDropsTheArrow(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("name,from,to", nil)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}

	plain := row(mod, measure([]module.Module{mod}, 0, columns, false))
	if !strings.Contains(plain, "->") {
		t.Errorf("row %q has no arrow, want one when there is no heading", plain)
	}

	headed := measure([]module.Module{mod}, 0, columns, true)
	if got := row(mod, headed); strings.Contains(got, "->") {
		t.Errorf("row %q keeps the arrow, want it dropped under a heading", got)
	}
	if got := header(headed); !strings.Contains(got, "FROM") || !strings.Contains(got, "TO") {
		t.Errorf("header %q does not name both version columns", got)
	}
}

// TestMeasureDropsEmptyColumns checks that a column every module leaves empty is
// not rendered, since a heading with nothing under it is only noise.
func TestMeasureDropsEmptyColumns(t *testing.T) {
	// No advisories, no hint, nothing requiring it.
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure([]module.Module{mod}, 0, columns, false)

	for _, absent := range []string{module.ColumnLabel, module.ColumnCVE, module.ColumnHint} {
		if slices.Contains(l.columns, absent) {
			t.Errorf("column %q was kept though no module fills it", absent)
		}
	}
	for _, present := range []string{module.ColumnName, module.ColumnFrom, module.ColumnTo} {
		if !slices.Contains(l.columns, present) {
			t.Errorf("column %q was dropped though it has content", present)
		}
	}
}
