package module

import (
	"slices"
	"testing"
)

// TestPerConfigurationOneRowEach checks that a module in the build under several
// configurations becomes one row per configuration.
//
// A listing crams them into one cell otherwise, which is the wrong shape for the
// question a reader is asking: which upgrade belongs to which build. One row each
// lets them collapse the rows by eye instead of parsing a list.
func TestPerConfigurationOneRowEach(t *testing.T) {
	for _, tc := range []struct {
		name string
		tags []string
		want [][]string
	}{{
		// Reached two ways, so it is two rows naming one configuration each.
		name: "several configurations",
		tags: []string{"*", "core && integration"},
		want: [][]string{{"*"}, {"core && integration"}},
	}, {
		name: "one configuration",
		tags: []string{"core && integration"},
		want: [][]string{{"core && integration"}},
	}, {
		// What excludes a module is not a build it is reached under, it is a remark
		// about the build that reaches it: "in the plain build, and lost once
		// integration is set" is one statement. Split across rows, one row claims
		// the reach without the exclusion and the other the reverse.
		name: "an exclusion stays with the configuration it qualifies",
		tags: []string{"*", "!integration"},
		want: [][]string{{"*", "!integration"}},
	}, {
		// Several configurations reach it and something excludes it elsewhere. The
		// exclusion qualifies every row, since it is a fact about the module.
		name: "an exclusion qualifies each configuration",
		tags: []string{"*", "integration", "!plugins"},
		want: [][]string{{"*", "!plugins"}, {"integration", "!plugins"}},
	}, {
		// Nothing configuration-specific to say, and nothing to split: either every
		// build reaches it or none does, and the empty column says which.
		name: "no configurations",
		tags: nil,
		want: [][]string{nil},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			in := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
			in.Tags = tc.tags

			got := PerConfiguration([]Module{in})

			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !slices.Equal(got[i].Tags, tc.want[i]) {
					t.Errorf("row %d holds %v, want %v", i, got[i].Tags, tc.want[i])
				}
				if got[i].Name != in.Name {
					t.Errorf("row %d is %s, want every row to name the module", i, got[i].Name)
				}
			}
		})
	}
}

// TestPerConfigurationCopiesTheRest checks that a row carries everything the module
// did, since none of it was gathered per configuration.
//
// What a sweep found is unioned across the configurations before a module is
// annotated, so an advisory belongs to the module rather than to one of its rows.
// Dropping the fields would read as though only one build carried it.
func TestPerConfigurationCopiesTheRest(t *testing.T) {
	in := mod(t, "example.com/a", "v1.0.0", "v1.1.0", true)
	in.Tags = []string{"*", "integration"}
	in.Vulns = []string{"CVE-2026-1"}
	in.RequiredBy = []string{"example.com/b"}
	in.Fixes = []string{"example.com/c"}
	in.Reachable = 1
	in.Deprecated = "use something else"

	got := PerConfiguration([]Module{in})
	if len(got) != 2 {
		t.Fatalf("got %d rows, want one per configuration", len(got))
	}
	for i, row := range got {
		if !slices.Equal(row.Vulns, in.Vulns) {
			t.Errorf("row %d advisories = %v, want %v", i, row.Vulns, in.Vulns)
		}
		if !slices.Equal(row.RequiredBy, in.RequiredBy) {
			t.Errorf("row %d required by %v, want %v", i, row.RequiredBy, in.RequiredBy)
		}
		if !slices.Equal(row.Fixes, in.Fixes) {
			t.Errorf("row %d fixes %v, want %v", i, row.Fixes, in.Fixes)
		}
		if row.Reachable != in.Reachable || row.Deprecated != in.Deprecated || row.Indirect != in.Indirect {
			t.Errorf("row %d lost a field the module carried", i)
		}
	}
}

// TestPerConfigurationKeepsOrder checks that the rows of one module stay together,
// in the order the configurations were recorded.
func TestPerConfigurationKeepsOrder(t *testing.T) {
	first := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
	first.Tags = []string{"*", "integration"}
	second := mod(t, "example.com/b", "v1.0.0", "v1.1.0", false)

	got := PerConfiguration([]Module{first, second})

	want := []string{"example.com/a", "example.com/a", "example.com/b"}
	names := make([]string, 0, len(got))
	for _, m := range got {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
	if got[0].Tags[0] != "*" {
		t.Errorf("first row holds %v, want the configurations in the order recorded", got[0].Tags)
	}
}
