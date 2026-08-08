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
//
// This is a rule of the human listing alone. A parseable row keeps every column
// that was asked for, because a parser addresses a column by its position, so
// dropping one would shift everything after it.
func TestMeasureDropsEmptyColumns(t *testing.T) {
	// No advisories, no hint, nothing requiring it.
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure([]module.Module{mod}, 0, columns, false, budget{columns: 200, limited: true})

	for _, absent := range []string{module.ColumnLabel, module.ColumnVuln, module.ColumnHint} {
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
//
// This is a rule of the human listing alone. Stopping at the last column with
// content is what makes a row's length depend on what it carries, so a parseable
// row does not stop: it renders every column and never elides. See
// TestFieldRowGivesEveryColumnOneField.
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
//
// This is a rule of the human listing alone, as the test above is.
func TestMeasureDropsEmptyColumnsWithHeaders(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	l := measure([]module.Module{mod}, 0, columns, true, budget{columns: 200, limited: true})

	for _, absent := range []string{module.ColumnVuln, module.ColumnHint, module.ColumnLabel} {
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
// configuration fanout belongs where the rows are printed. A configuration is a
// presentation of one requirement rather than a requirement of its own, so these
// rows go no further.
//
// The requirement split is the other kind and happens earlier, before the filter,
// since it decides what a row is about. See TestPresentFiltersTheRowsItPrints.
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

// TestCountCoolingIsWhatTheCooldownWithheld checks that the count reported alongside "All
// modules are up to date" is the number of upgrades the cooldown held back.
//
// The count exists to tell the two silences apart: nothing newer was published, or something
// was and is still settling. Only the second is answered by --cooldown=0, so a reader deciding
// whether to pass it relies on this counting what that flag would reveal -- and on it counting
// nothing that the flag would not.
func TestCountCoolingIsWhatTheCooldownWithheld(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()
	module.SetCooldown(7 * day)
	defer module.SetCooldown(0)

	// One entry per reason a module is, or is not, an upgrade the cooldown is withholding.
	tests := []struct {
		name     string
		modName  string
		from, to string
		released time.Time
		ignored  bool
		want     int
	}{{
		name: "a fresh release is waited on",
		from: "v1.0.0", to: "v1.1.0", released: now.Add(-1 * day),
		want: 1,
	}, {
		// Out long enough that the cooldown has nothing left to withhold.
		name: "a settled release is not",
		from: "v1.0.0", to: "v1.1.0", released: now.Add(-30 * day),
		want: 0,
	}, {
		// Already at its newest version, so no cooldown applies whatever its age.
		name: "a module with no upgrade is not",
		from: "v1.1.0", to: "v1.1.0", released: now.Add(-1 * day),
		want: 0,
	}, {
		// Withheld by the ignore list rather than by the cooldown, so --cooldown=0 would
		// not reveal it and it must not be counted as though it would.
		name: "an ignored module is not",
		from: "v1.0.0", to: "v1.1.0", released: now.Add(-1 * day), ignored: true,
		want: 0,
	}, {
		// The toolchain is upgraded by its own path, so upgradable skips it and the count
		// has to skip it identically.
		name: "the toolchain is not", modName: ToolchainName,
		from: "v1.0.0", to: "v1.1.0", released: now.Add(-1 * day),
		want: 0,
	}, {
		// An unknown release date is not evidence of settling, so nothing is waited on.
		name: "a release with no date is not",
		from: "v1.0.0", to: "v1.1.0", released: time.Time{},
		want: 0,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.modName
			if name == "" {
				name = "example.com/m"
			}
			mod := mustModule(t, name, tc.from, tc.to)
			mod.Released = tc.released
			mod.Ignored = tc.ignored
			modules := []module.Module{mod}

			if got := countCooling(modules); got != tc.want {
				t.Errorf("countCooling() = %d, want %d", got, tc.want)
			}
			// The invariant the count rests on: it is exactly the gap between what would
			// be offered with the cooldown ignored and what is offered with it applied.
			// Asserted as well as the number, since those two drifting apart is what
			// would make the count lie.
			withheld := len(upgradable(modules, true)) - len(upgradable(modules, false))
			if got := countCooling(modules); got != withheld {
				t.Errorf("countCooling() = %d, want %d, the upgrades the cooldown withheld", got, withheld)
			}
		})
	}

	// And the counts add up over a mixed list, which is what a run actually reports.
	fresh := mustModule(t, "example.com/fresh", "v1.0.0", "v1.1.0")
	fresh.Released = now.Add(-1 * day)
	alsoFresh := mustModule(t, "example.com/also-fresh", "v2.0.0", "v2.1.0")
	alsoFresh.Released = now.Add(-2 * day)
	settled := mustModule(t, "example.com/settled", "v3.0.0", "v3.1.0")
	settled.Released = now.Add(-30 * day)
	if got := countCooling([]module.Module{fresh, alsoFresh, settled}); got != 2 {
		t.Errorf("countCooling() = %d, want 2 of the three waited on", got)
	}
}

// TestFieldRowGivesEveryColumnOneField pins the contract a parser depends on: the
// field count is decided by the columns asked for, never by what a row carries.
//
// Four separate things used to make it vary. measure dropped a column no module
// filled; row stopped after the last column with content; the arrow between the
// versions was its own whitespace-delimited field; and a multi-value cell joined
// with ", " emitted one field per value, so a module with 24 advisories produced a
// 32-field row beside 6-field neighbours. "awk '{print $7}'" therefore addressed a
// different column on almost every line.
func TestFieldRowGivesEveryColumnOneField(t *testing.T) {
	// Nothing in the trailing columns, which is what used to shorten a row.
	bare := mustModule(t, "example.com/bare", "v1.0.0", "v1.1.0")

	// Several values in one cell, which is what used to lengthen one.
	crowded := mustModule(t, "example.com/crowded", "v1.0.0", "v2.0.0")
	crowded.Vulns = []string{"CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0003"}
	crowded.RequiredBy = []string{"cmd/one", "cmd/two"}

	columns, err := module.ParseColumns("", allColumns())
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	wanted := columns.Ordered()

	for _, mod := range []module.Module{bare, crowded} {
		got := fieldRow(mod, wanted)
		if n := len(strings.Split(got, fieldSeparator)); n != len(wanted) {
			t.Errorf("%s: row has %d fields, want %d for %d columns:\n%q",
				mod.Name, n, len(wanted), len(wanted), got)
		}
		// awk's default splitting is on runs of whitespace, which is how the
		// user writes it, so that has to agree with the tab count too.
		if n := len(strings.Fields(got)); n != len(wanted) {
			t.Errorf("%s: row splits into %d whitespace fields, want %d:\n%q",
				mod.Name, n, len(wanted), got)
		}
	}

	// The heading is addressed by the same index as the rows beneath it.
	if n := len(strings.Split(fieldHeader(wanted), fieldSeparator)); n != len(wanted) {
		t.Errorf("heading has %d fields, want %d", n, len(wanted))
	}
}

// TestFieldRowKeepsTheArrowOut pins that the versions are two fields with nothing
// between them.
//
// The human listing joins them with " -> " when no heading names them, which is
// three whitespace-delimited tokens where a parser expects two: every column after
// TO shifted by one.
func TestFieldRowKeepsTheArrowOut(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	columns, err := module.ParseColumns("name,from,to", nil)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	got := fieldRow(mod, columns.Ordered())
	if strings.Contains(got, "->") {
		t.Errorf("row %q carries the arrow, want it left to the human listing", got)
	}
	fields := strings.Split(got, fieldSeparator)
	if len(fields) != 3 {
		t.Fatalf("row %q has %d fields, want 3", got, len(fields))
	}
	if fields[1] != "1.0.0" || fields[2] != "1.1.0" {
		t.Errorf("versions are %q and %q, want the two on their own", fields[1], fields[2])
	}
}

// TestFieldRendersValuesForAParser pins that a field carries the canonical value
// rather than the readable one.
//
// The two differ in more than padding, so a parser reading the human listing gets
// values it cannot use: an age rounded down to "3d" has lost the hours and needs a
// suffix parsed off, a label compressed to "V" needs expanding, and a
// pseudo-version abbreviated to its commit no longer says what the module resolves
// to.
func TestFieldRendersValuesForAParser(t *testing.T) {
	restore := module.SetClock(func() time.Time {
		return time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	})
	defer restore()

	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	mod.Released = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	mod.Vulns = []string{"CVE-0000-0001", "CVE-0000-0002"}

	tests := []struct {
		name   string
		column string
		want   string
		// human is what the readable listing says, which must NOT be the field.
		human string
	}{{
		// Three days exactly, so the readable form rounds to "3d".
		name:   "an age is a count of seconds",
		column: module.ColumnAge,
		want:   "259200",
		human:  "3d",
	}, {
		name:   "advisories join without a space",
		column: module.ColumnVuln,
		want:   "CVE-0000-0001,CVE-0000-0002",
		human:  "CVE-0000-0001, CVE-0000-0002",
	}, {
		// Nothing is waiting, and a blank would emit no field at all.
		name:   "an empty value is still one field",
		column: module.ColumnCooldown,
		want:   emptyField,
		human:  "",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := field(mod, tc.column); got != tc.want {
				t.Errorf("field(%s) = %q, want %q", tc.column, got, tc.want)
			}
			if got := cell(mod, tc.column); got != tc.human {
				t.Errorf("cell(%s) = %q, want the readable %q left alone",
					tc.column, got, tc.human)
			}
		})
	}
}

// TestFieldNamesTheLabelKeys pins that a parseable row spells a label as the
// --labels key it names, whatever the width.
//
// The letters are an abbreviation for a narrow column, and which of the two the
// human listing uses depends on --width. A parser wants the spelling it could pass
// back to --labels, and wants it not to depend on how wide the output is.
func TestFieldNamesTheLabelKeys(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	mod.Vulns = []string{"CVE-0000-0001"}
	mod.Reachable = 1

	defer func(prev bool) { module.Wide = prev }(module.Wide)
	for _, wide := range []bool{false, true} {
		module.Wide = wide
		got := field(mod, module.ColumnLabel)
		if !strings.Contains(got, module.FilterVulnReachable) {
			t.Errorf("Wide=%v: label field %q does not name the selector key", wide, got)
		}
		if strings.Contains(got, " ") {
			t.Errorf("Wide=%v: label field %q holds a space, so it is two fields", wide, got)
		}
	}
}

// TestFieldNeverElides pins that a parseable field carries the whole value however
// narrow the listing is.
//
// The human listing fits a long list to the column by dropping entries and saying
// how many went, as "cmd/one cmd/two +3 more". That is two defects at once for a
// parser: the marker is extra whitespace-delimited tokens, and the entries it
// replaced are simply gone, with no way to ask for them. A width describes a
// terminal, and there is no terminal here, so nothing is fitted to it.
func TestFieldNeverElides(t *testing.T) {
	mod := mustModule(t, "example.com/m", "v1.0.0", "v1.1.0")
	mod.RequiredBy = []string{"cmd/one", "cmd/two", "cmd/three", "cmd/four", "cmd/five"}
	mod.Vulns = []string{"CVE-0000-0001", "CVE-0000-0002", "CVE-0000-0003", "CVE-0000-0004"}

	for _, column := range []string{module.ColumnRequiredBy, module.ColumnVuln} {
		got := field(mod, column)
		if strings.Contains(got, "more") || strings.Contains(got, "+") {
			t.Errorf("%s field %q elides, want the whole value", column, got)
		}
		if strings.ContainsAny(got, " \t") {
			t.Errorf("%s field %q holds whitespace, so it is several fields", column, got)
		}
	}
	// Every entry survives, which is the point of not eliding.
	required := field(mod, module.ColumnRequiredBy)
	for _, want := range mod.RequiredBy {
		if !strings.Contains(required, want) {
			t.Errorf("required-by field %q omits %q", required, want)
		}
	}
	if n := len(strings.Split(required, valueSeparator)); n != len(mod.RequiredBy) {
		t.Errorf("required-by field %q holds %d values, want %d", required, n, len(mod.RequiredBy))
	}
}

// TestPresentFiltersTheRowsItPrints checks that a filter selects over the rows a
// listing prints.
//
// The wiring, which no test of Apply on its own would catch. A workspace member
// standing past everything published makes its row a downgrade, while the merged
// row it was split from is an ordinary upgrade: filtering before the split asked
// the question of a version no member requires, so --labels=downgrade withheld a
// row the default listing printed.
func TestPresentFiltersTheRowsItPrints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels string
		// want names the from field of each row expected, in order.
		want []string
		// marked is the from field of the row whose label must name a downgrade,
		// empty where no row should carry one.
		marked string
	}{{
		// Both requirements are worth reporting: one is behind and the other stands
		// past what is published. Ordered by the default sort, which leads with how
		// disruptive the change is, so the wider move comes first.
		name:   "the default keeps both requirements",
		want:   []string{"1.9.0", "1.0.0"},
		marked: "1.9.0",
	}, {
		// The row the default listing marks, and the whole of what the key selects.
		name:   "the key selects the row it marks",
		labels: "downgrade",
		want:   []string{"1.9.0"},
		marked: "1.9.0",
	}, {
		// Its negation leaves the ordinary upgrade, which is how a listing asks for
		// the upgrades alone.
		name:   "the negation drops it",
		labels: "-downgrade",
		want:   []string{"1.0.0"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			// The ws6 shape: "old" requires the older version, "ahead" requires one
			// past anything published, and the merged row carries the oldest.
			lib := mustModule(t, "example.com/lib", "v1.0.0", "v1.1.0")
			lib.RequiredBy = []string{"ahead", "old"}
			lib.Required = map[string][]string{"v1.0.0": {"old"}, "v1.9.0": {"ahead"}}

			filter, err := module.ParseFilter(tc.labels, module.DefaultFilters())
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.labels, err)
			}
			columns, err := module.ParseColumns("name,label,from,to,required_by", allColumns())
			if err != nil {
				t.Fatalf("ParseColumns: %v", err)
			}
			sorter, err := module.ParseSort("", module.DefaultSorts())
			if err != nil {
				t.Fatalf("ParseSort: %v", err)
			}

			var buf bytes.Buffer
			defer setStdout(&buf)()

			if err := present([]module.Module{lib}, view{
				sort:    sorter,
				filter:  filter,
				format:  module.FormatTSV,
				columns: columns,
			}); err != nil {
				t.Fatalf("present: %v", err)
			}

			rows := strings.Split(strings.TrimSpace(buf.String()), "\n")
			if buf.Len() == 0 {
				rows = nil
			}
			if len(rows) != len(tc.want) {
				t.Fatalf("got %d rows, want %d:\n%s", len(rows), len(tc.want), buf.String())
			}
			for i, row := range rows {
				fields := strings.Split(row, "\t")
				if len(fields) < 3 {
					t.Fatalf("row %d has %d fields, want the columns asked for: %q", i, len(fields), row)
				}
				// name, label, from: the from field is the third.
				if got := fields[2]; got != tc.want[i] {
					t.Errorf("row %d requires %s, want %s", i, got, tc.want[i])
				}
				// The letter is expanded to its key in a parseable row. Asserted as
				// the literal, the spelling being what a reader passes back.
				marked := strings.Contains(fields[1], "downgrade")
				if want := fields[2] == tc.marked; marked != want {
					t.Errorf("row %d labels %q, want downgrade named: %v", i, fields[1], want)
				}
			}
		})
	}
}
