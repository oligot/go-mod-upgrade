package app

import (
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
	l := measure(modules, 0)

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
	l := measure(modules, 0)

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
