package app

import (
	"slices"
	"testing"

	"github.com/Masterminds/semver/v3"
)

// fix parses the version an advisory is fixed in, failing the test if it is
// unusable.
func fix(t *testing.T, v string) *semver.Version {
	t.Helper()
	parsed, err := semver.NewVersion(v)
	if err != nil {
		t.Fatalf("parsing %q: %v", v, err)
	}
	return parsed
}

// TestParseRequires reads the require block of a candidate's go.mod, which is
// what says whether upgrading it would lift a vulnerable module.
func TestParseRequires(t *testing.T) {
	const body = `
module github.com/mattn/go-isatty

go 1.15

require golang.org/x/sys v0.28.0
`
	asks := parseRequires("go.mod", []byte(body))
	if got, want := asks["golang.org/x/sys"], "v0.28.0"; got != want {
		t.Errorf("x/sys = %q, want %q", got, want)
	}
}

// TestParseRequiresTolerantOfNewerSyntax checks that an unknown directive does
// not lose the requirements.
//
// A dependency may have been written for a newer Go than this build knows, and
// giving up on its go.mod would silently drop it from the analysis -- reading as
// "this upgrade resolves nothing" rather than "we could not tell".
func TestParseRequiresTolerantOfNewerSyntax(t *testing.T) {
	const body = `
module example.com/m

go 1.99

somethingnew fancy-value

require golang.org/x/sys v0.47.0
`
	asks := parseRequires("go.mod", []byte(body))
	if got, want := asks["golang.org/x/sys"], "v0.47.0"; got != want {
		t.Errorf("x/sys = %q, want %q despite the unknown directive", got, want)
	}
}

func TestParseRequiresInvalid(t *testing.T) {
	// A go.mod that cannot be parsed at all yields nothing rather than panicking.
	if got := parseRequires("go.mod", []byte("module\x00\x00 not a mod file")); len(got) != 0 {
		t.Errorf("got %v, want no requirements", got)
	}
}

// TestResolversPicksOnlyUpgradesThatReachTheFix pins the arithmetic this feature
// exists for.
//
// Go selects the highest version any module asks for, so upgrading a dependent
// lifts a vulnerable module only when the dependent's own go.mod asks for a
// version at or past the fix. This is the real case from go-mod-upgrade's own
// tree: x/sys carries an advisory fixed in v0.44.0, and of its three dependents
// only x/term asks for anything that high.
func TestResolversPicksOnlyUpgradesThatReachTheFix(t *testing.T) {
	needed := map[string]*semver.Version{"golang.org/x/sys": fix(t, "v0.44.0")}
	asks := map[string]requires{
		// Latest go-isatty still asks for far less than the fix.
		"github.com/mattn/go-isatty": {"golang.org/x/sys": "v0.28.0"},
		// So does go-colorable.
		"github.com/mattn/go-colorable": {"golang.org/x/sys": "v0.29.0"},
		// x/term is the one that would carry x/sys past it.
		"golang.org/x/term": {"golang.org/x/sys": "v0.47.0"},
		// A module not requiring it at all cannot resolve anything.
		"github.com/fatih/color": {"github.com/mattn/go-isatty": "v0.0.20"},
	}

	got := whatFixes(needed, asks)
	want := []string{"golang.org/x/term"}
	if !slices.Equal(got["golang.org/x/sys"], want) {
		t.Errorf("got %v, want %v: only an upgrade reaching the fix resolves it",
			got["golang.org/x/sys"], want)
	}
}

// TestResolversAtTheFixExactly checks the boundary, since a dependent asking for
// exactly the fixed version does resolve the advisory.
func TestResolversAtTheFixExactly(t *testing.T) {
	needed := map[string]*semver.Version{"example.com/v": fix(t, "v1.2.0")}
	cases := []struct {
		name string
		asks string
		want bool
	}{
		{"below the fix", "v1.1.9", false},
		{"exactly the fix", "v1.2.0", true},
		{"above the fix", "v1.3.0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := whatFixes(needed, map[string]requires{
				"example.com/dependent": {"example.com/v": c.asks},
			})
			if fixed := len(got["example.com/v"]) > 0; fixed != c.want {
				t.Errorf("asking for %s: resolved = %v, want %v", c.asks, fixed, c.want)
			}
		})
	}
}

// TestResolversNamesEveryResolver checks that all the upgrades which would work
// are reported, since a reader may prefer one over another.
func TestResolversNamesEveryResolver(t *testing.T) {
	needed := map[string]*semver.Version{"example.com/v": fix(t, "v1.0.0")}
	got := whatFixes(needed, map[string]requires{
		"example.com/b": {"example.com/v": "v1.1.0"},
		"example.com/a": {"example.com/v": "v2.0.0"},
	})
	// Sorted, so a listing does not shuffle between runs.
	want := []string{"example.com/a", "example.com/b"}
	if !slices.Equal(got["example.com/v"], want) {
		t.Errorf("got %v, want %v", got["example.com/v"], want)
	}
}

// TestResolversIgnoresUnparseableVersions checks that a requirement we cannot
// read is treated as resolving nothing, rather than as resolving everything.
func TestResolversIgnoresUnparseableVersions(t *testing.T) {
	needed := map[string]*semver.Version{"example.com/v": fix(t, "v1.0.0")}
	got := whatFixes(needed, map[string]requires{
		"example.com/dependent": {"example.com/v": "not-a-version"},
	})
	if len(got) != 0 {
		t.Errorf("got %v, want nothing resolved by an unreadable requirement", got)
	}
}
