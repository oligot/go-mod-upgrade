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

// TestPerRequirementOneRowPerVersion checks that a module the workspace members
// disagree about becomes one row per version required, each naming the members
// requiring it.
//
// From is the oldest of those versions, being the one most in need of the upgrade.
// One row reporting it for every member says a member already at the newest version
// is two releases behind, and offers it an upgrade it has nothing to take.
func TestPerRequirementOneRowPerVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required map[string][]string
		want     []string
		by       [][]string
	}{{
		// The misreport: parent requires what is available, sub is behind, and one
		// row claiming 0.3.0 for both reports parent as behind too.
		name:     "members disagree",
		required: map[string][]string{"v0.3.0": {"sub"}, "v0.40.0": {"parent"}},
		want:     []string{"0.3.0", "0.40.0"},
		by:       [][]string{{"sub"}, {"parent"}},
	}, {
		// Ordered as versions, not as strings: "v0.10.0" precedes "v0.9.0"
		// alphabetically, which would print the newer requirement first.
		name:     "ordered oldest first",
		required: map[string][]string{"v0.9.0": {"a"}, "v0.10.0": {"b"}},
		want:     []string{"0.9.0", "0.10.0"},
		by:       [][]string{{"a"}, {"b"}},
	}, {
		// Several members at one version share its row, that being the whole truth
		// about them.
		name:     "members grouped by the version they require",
		required: map[string][]string{"v0.3.0": {"one", "two"}, "v0.40.0": {"three"}},
		want:     []string{"0.3.0", "0.40.0"},
		by:       [][]string{{"one", "two"}, {"three"}},
	}, {
		// Agreement is the ordinary case and has nothing to distinguish, so the
		// module keeps the single row and the RequiredBy it arrived with.
		name:     "members agree",
		required: map[string][]string{"v0.3.0": {"one", "two"}},
		want:     []string{"1.0.0"},
		by:       [][]string{{"everyone"}},
	}, {
		name:     "not a workspace",
		required: nil,
		want:     []string{"1.0.0"},
		by:       [][]string{{"everyone"}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			in := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
			in.RequiredBy = []string{"everyone"}
			in.Required = tc.required

			got := PerRequirement([]Module{in})

			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i].From.String() != tc.want[i] {
					t.Errorf("row %d requires %s, want %s", i, got[i].From, tc.want[i])
				}
				if !slices.Equal(got[i].RequiredBy, tc.by[i]) {
					t.Errorf("row %d required by %v, want %v", i, got[i].RequiredBy, tc.by[i])
				}
				// Which version is available is a property of the module, so every
				// row is offered the same one.
				if got[i].To.String() != "1.1.0" {
					t.Errorf("row %d offers %s, want every row to offer 1.1.0", i, got[i].To)
				}
				if got[i].Name != in.Name {
					t.Errorf("row %d is %s, want every row to name the module", i, got[i].Name)
				}
			}
		})
	}
}

// TestJoinVersionsNamesEveryRequirement checks that a listing showing one row per
// module names every version the members require, oldest first.
//
// A person reads one line per module, so the versions are crowded into the one
// cell. Empty where the members agree, leaving the ordinary single version to
// render rather than a list of one.
func TestJoinVersionsNamesEveryRequirement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required map[string][]string
		want     string
	}{{
		name:     "members disagree",
		required: map[string][]string{"v0.3.0": {"sub"}, "v0.40.0": {"parent"}},
		want:     "0.3.0,0.40.0",
	}, {
		name:     "ordered oldest first",
		required: map[string][]string{"v0.10.0": {"b"}, "v0.9.0": {"a"}},
		want:     "0.9.0,0.10.0",
	}, {
		// Nothing to distinguish, so the caller renders the single version it
		// already has.
		name:     "members agree",
		required: map[string][]string{"v0.3.0": {"one", "two"}},
		want:     "",
	}, {
		name:     "not a workspace",
		required: nil,
		want:     "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := JoinVersions(tc.required); got != tc.want {
				t.Errorf("JoinVersions() = %q, want %q", got, tc.want)
			}
		})
	}
}
