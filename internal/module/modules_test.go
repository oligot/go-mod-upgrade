package module

import (
	"slices"
	"testing"
)

// TestModulesFilterKeepsWhatTheChainSelects checks that filtering a result set
// keeps the rows the chain names and drops the rest.
func TestModulesFilterKeepsWhatTheChainSelects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels string
		want   []string
	}{{
		// The default keeps whatever differs from what is installed.
		name: "the default",
		want: []string{"example.com/behind", "example.com/indirect"},
	}, {
		name:   "one key",
		labels: "indirect",
		want:   []string{"example.com/indirect"},
	}, {
		name:   "the negation",
		labels: "-indirect",
		want:   []string{"example.com/behind"},
	}, {
		name:   "everything",
		labels: "all",
		want:   []string{"example.com/behind", "example.com/current", "example.com/indirect"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			behind := mod(t, "example.com/behind", "v1.0.0", "v1.1.0", false)
			current := mod(t, "example.com/current", "v1.1.0", "v1.1.0", false)
			indirect := mod(t, "example.com/indirect", "v1.0.0", "v1.1.0", true)

			show, err := ParseFilter(tc.labels, DefaultFilters())
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.labels, err)
			}

			got := Modules{behind, current, indirect}.Filter(show)

			names := make([]string, 0, len(got))
			for _, mod := range got {
				names = append(names, mod.Name)
			}
			if !slices.Equal(names, tc.want) {
				t.Errorf("kept %v, want %v", names, tc.want)
			}
		})
	}
}

// TestModulesSplitPartitionsTheMembers checks that splitting a workspace row
// divides its members rather than copying them.
//
// This is the property that lets the split rows go on to the upgrade: each member
// appears under exactly one row, so applying every row upgrades each member once.
// A fanout that repeated a member would upgrade it once per row.
func TestModulesSplitPartitionsTheMembers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required map[string][]string
		// want is every member the rows should name between them.
		want []string
	}{{
		name:     "members disagree",
		required: map[string][]string{"v1.0.0": {"old"}, "v1.9.0": {"ahead"}},
		want:     []string{"ahead", "old"},
	}, {
		name: "several members at one version",
		required: map[string][]string{
			"v1.0.0": {"one", "two"},
			"v1.9.0": {"three"},
		},
		want: []string{"one", "three", "two"},
	}, {
		// Nothing to divide, so the row keeps the members it arrived with.
		name:     "members agree",
		required: nil,
		want:     []string{"everyone"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			in := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
			in.RequiredBy = []string{"everyone"}
			in.Required = tc.required

			got := Modules{in}.Split()

			// Every member named once across the rows: the union is the whole set,
			// and no two rows name the same member.
			var union []string
			for _, row := range got {
				for _, member := range row.RequiredBy {
					if slices.Contains(union, member) {
						t.Errorf("member %q named by more than one row", member)
					}
					union = append(union, member)
				}
			}
			slices.Sort(union)
			if !slices.Equal(union, tc.want) {
				t.Errorf("rows name %v between them, want %v", union, tc.want)
			}
		})
	}
}

// TestModulesCoalesceIsTheInverseOfSplit checks that combining the rows of a
// module returns what splitting it began with.
func TestModulesCoalesceIsTheInverseOfSplit(t *testing.T) {
	in := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
	in.RequiredBy = []string{"ahead", "old"}
	in.Required = map[string][]string{"v1.0.0": {"old"}, "v1.9.0": {"ahead"}}

	got := Modules{in}.Split().Coalesce()

	if len(got) != 1 {
		t.Fatalf("got %d rows, want the module combined into 1", len(got))
	}
	if got[0].From.String() != "1.0.0" {
		t.Errorf("stands at %s, want the oldest requirement 1.0.0", got[0].From)
	}
	if joined := JoinVersions(got[0].Required); joined != "1.0.0,1.9.0" {
		t.Errorf("names %q, want both requirements", joined)
	}
	if !slices.Equal(got[0].RequiredBy, []string{"ahead", "old"}) {
		t.Errorf("required by %v, want every member back", got[0].RequiredBy)
	}
}

// TestModulesSortByIsStable checks that sorting leaves rows the chain cannot
// distinguish in the order they arrived.
//
// A workspace module becomes several rows differing only in the version required,
// and a chain saying nothing about versions must not shuffle them: the order they
// were split in is the order their members were read in.
func TestModulesSortByIsStable(t *testing.T) {
	first := mod(t, "example.com/same", "v1.0.0", "v1.1.0", false)
	first.RequiredBy = []string{"first"}
	second := mod(t, "example.com/same", "v1.0.0", "v1.1.0", false)
	second.RequiredBy = []string{"second"}

	// A chain naming the name alone, which cannot tell two rows of one module apart.
	by, err := ParseSort("name", DefaultSorts())
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}

	got := Modules{first, second}.SortBy(by)

	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if !slices.Equal(got[0].RequiredBy, []string{"first"}) {
		t.Errorf("leading row is required by %v, want the one that arrived first", got[0].RequiredBy)
	}
}

// TestModulesByNameGroupsTheRows checks that the rows of one module are grouped
// together whatever order they arrive in.
func TestModulesByNameGroupsTheRows(t *testing.T) {
	a1 := mod(t, "example.com/a", "v1.0.0", "v1.1.0", false)
	b := mod(t, "example.com/b", "v1.0.0", "v1.1.0", false)
	a2 := mod(t, "example.com/a", "v1.2.0", "v1.3.0", false)

	got := Modules{a1, b, a2}.ByName()

	if len(got) != 2 {
		t.Fatalf("grouped into %d modules, want 2", len(got))
	}
	if len(got["example.com/a"]) != 2 {
		t.Errorf("example.com/a has %d rows, want 2 even when they arrive apart",
			len(got["example.com/a"]))
	}
	if len(got["example.com/b"]) != 1 {
		t.Errorf("example.com/b has %d rows, want 1", len(got["example.com/b"]))
	}
}
