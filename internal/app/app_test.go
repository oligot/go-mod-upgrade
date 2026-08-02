package app

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

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
	l := measure(modules, 0, columns, false, budget{columns: 200, limited: true})

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
	l := measure(modules, 0, columns, false, budget{columns: 200, limited: true})

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
	l := measure(modules, 0, columns, false, budget{columns: 200, limited: true})

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

	plain := row(mod, measure([]module.Module{mod}, 0, columns, false, budget{columns: 200, limited: true}))
	if !strings.Contains(plain, "->") {
		t.Errorf("row %q has no arrow, want one when there is no heading", plain)
	}

	headed := measure([]module.Module{mod}, 0, columns, true, budget{columns: 200, limited: true})
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
	l := measure([]module.Module{mod}, 0, columns, false, budget{columns: 200, limited: true})

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

// TestRowKeepsTheLastColumnWhole pins that a value is not elided for want of a
// width the row does not need.
//
// A column holds its width so the next one aligns, so the last needs no padding.
// But a width is also what a column elides against: asking for none truncated
// the value to nothing, which showed up as ". +4 more" where five workspace
// members would have fitted.
func TestRowKeepsTheLastColumnWhole(t *testing.T) {
	mod := mustModule(t, "golang.org/x/sys", "v0.26.0", "v0.47.0")
	mod.RequiredBy = []string{".", "cmd/osapilint", "cmd/osgen", "osotel", "osprom"}

	// A second module keeps the column from being the widest thing measured.
	other := mustModule(t, "github.com/yuin/goldmark", "v1.4.13", "v1.8.5")
	other.RequiredBy = []string{"cmd/osapilint"}

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	modules := []module.Module{mod, other}

	for _, b := range []budget{
		{columns: 200, limited: true},
		{limited: false},
	} {
		got := row(mod, measure(modules, 0, columns, false, b))
		for _, want := range mod.RequiredBy {
			if !strings.Contains(got, want) {
				t.Errorf("budget %+v: row %q omits %q", b, got, want)
			}
		}
		if strings.Contains(got, "more") {
			t.Errorf("budget %+v: row %q elides a value that fits", b, got)
		}
	}
}

// TestMeasureDropsEmptyColumnsWithHeaders pins that a heading cannot resurrect a
// column no module fills.
//
// The heading's own width was applied before the emptiness check, so every column
// stayed alive whenever headings were on -- an ADVISORY column with no advisory
// under it, taking room from what did have something to say.
func TestMeasureDropsEmptyColumnsWithHeaders(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure([]module.Module{mod}, 0, columns, true, budget{columns: 200, limited: true})

	for _, absent := range []string{module.ColumnCVE, module.ColumnHint, module.ColumnLabel} {
		if slices.Contains(l.columns, absent) {
			t.Errorf("column %q survived with headings on, though nothing fills it", absent)
		}
	}
}

// TestRelativeToNamesTheRoot checks that the workspace root is named for its
// directory rather than as ".".
//
// filepath.Rel writes the base directory itself as ".", which in a list of
// workspace members reads as nothing at all: "., cmd/osgen, osotel" tells a
// reader less than "opensearch-go cmd/osgen osotel".
func TestRelativeToNamesTheRoot(t *testing.T) {
	all := []string{
		"/src/opensearch-go",
		"/src/opensearch-go/cmd/osgen",
		"/src/opensearch-go/osotel",
	}
	got := relativeTo(all, all)
	want := []string{"opensearch-go", "cmd/osgen", "osotel"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRowRendersTags pins that the configurations reaching a module reach a
// rendered row.
//
// This is the gap that let the labels vanish once already: the column was
// computed, measured and tested in isolation, but nothing asserted that a row
// contained it, so removing the render arm broke the output while every test
// still passed.
// TestListModulesOneRowPerConfiguration checks that a listing prints a module once
// per configuration reaching it.
//
// This is the wiring, which no test of PerConfiguration on its own would catch: the
// fanout has to happen where the rows are printed, and only there, so that a
// duplicate row can never reach the prompt or an upgrade.
func TestListModulesOneRowPerConfiguration(t *testing.T) {
	tagged := mustModule(t, "example.com/tagged", "v1.0.0", "v1.1.0")
	tagged.Tags = []string{defaultTagSet, "integration"}
	plain := mustModule(t, "example.com/plain", "v1.0.0", "v1.1.0")

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	sorter, err := module.ParseSort("", module.DefaultSorts())
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}

	var buf bytes.Buffer
	defer func(prev io.Writer) { color.Output = prev }(color.Output)
	color.Output = &buf

	listModules([]module.Module{tagged, plain}, view{
		sort:    sorter,
		columns: columns,
		width:   budget{columns: 200, limited: true},
	})

	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, "example.com/tagged") {
			rows = append(rows, line)
		}
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows for a module reached two ways, want one each:\n%s", len(rows), buf.String())
	}
	// Each row names one configuration, which is what tells them apart.
	if !strings.Contains(rows[0], defaultTagSet) || strings.Contains(rows[0], "integration") {
		t.Errorf("first row %q does not name the plain build alone", rows[0])
	}
	if !strings.Contains(rows[1], "integration") {
		t.Errorf("second row %q does not name the tagged configuration", rows[1])
	}
	// A module reached under everything, or nothing, is still one row.
	if got := strings.Count(buf.String(), "example.com/plain"); got != 1 {
		t.Errorf("got %d rows for a module naming no configuration, want 1", got)
	}
}

func TestRowRendersTags(t *testing.T) {
	tagged := mustModule(t, "example.com/tagged", "v1.0.0", "v1.1.0")
	tagged.Tags = []string{"integration"}

	plain := mustModule(t, "example.com/plain", "v1.0.0", "v1.1.0")

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	modules := []module.Module{tagged, plain}
	l := measure(modules, 0, columns, false, budget{columns: 200, limited: true})

	if got := row(tagged, l); !strings.Contains(got, "integration") {
		t.Errorf("row %q does not name the configuration reaching it", got)
	}
	// A module every configuration reaches carries nothing, so the column says
	// nothing about it rather than repeating itself.
	if got := row(plain, l); strings.Contains(got, "integration") {
		t.Errorf("row %q names a configuration the module does not need", got)
	}
}

// TestRowQuotesACompoundConfiguration pins that a configuration holding spaces is
// quoted in the listing.
//
// The column separates configurations with a space, so "integration && core" would
// otherwise read as three of them rather than one.
func TestRowQuotesACompoundConfiguration(t *testing.T) {
	mod := mustModule(t, "example.com/compound", "v1.0.0", "v1.1.0")
	mod.Tags = []string{defaultTagSet, "!(integration && core)"}

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	modules := []module.Module{mod}
	l := measure(modules, 0, columns, false, budget{columns: 200, limited: true})

	got := row(mod, l)
	if !strings.Contains(got, `"!(integration && core)"`) {
		t.Errorf("row %q does not quote the compound configuration", got)
	}
	// A single term needs no quotes, which would only cost width in a column that
	// has little to spare.
	if strings.Contains(got, `"`+defaultTagSet+`"`) {
		t.Errorf("row %q quotes a configuration that does not need it", got)
	}
}

// TestUpgradableHidesCooling checks that a release still settling is not offered for
// upgrade unless the caller asked for it.
//
// This is a gate of its own: the interactive path never passes through the listing's
// filter, so hiding a cooling module from --list and still offering it in the prompt
// is exactly the mismatch a second gate exists to prevent.
func TestUpgradableHidesCooling(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()
	module.SetCooldown(7 * day)
	defer module.SetCooldown(0)

	fresh := mustModule(t, "example.com/fresh", "v1.0.0", "v1.1.0")
	fresh.Released = now.Add(-1 * day)
	settled := mustModule(t, "example.com/settled", "v1.0.0", "v1.1.0")
	settled.Released = now.Add(-30 * day)
	all := []module.Module{fresh, settled}

	// Not asked for, so the prompt offers only what is recommended.
	var got []string
	for _, m := range upgradable(all, false) {
		got = append(got, m.Name)
	}
	if want := []string{"example.com/settled"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Asked for, so both are on offer.
	got = nil
	for _, m := range upgradable(all, true) {
		got = append(got, m.Name)
	}
	if want := []string{"example.com/fresh", "example.com/settled"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
