package app

import "testing"

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
