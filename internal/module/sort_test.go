package module

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
)

// TestMain leaves colour enabled so that the padding logic is exercised
// against real escape sequences; a test that ran with colour disabled would
// pass even if the escapes were counted as visible characters.
func TestMain(m *testing.M) {
	color.NoColor = false
	os.Exit(m.Run())
}

func mod(t *testing.T, name, from, to string, indirect bool) Module {
	t.Helper()
	f, err := semver.NewVersion(from)
	if err != nil {
		t.Fatalf("parsing %q: %v", from, err)
	}
	v, err := semver.NewVersion(to)
	if err != nil {
		t.Fatalf("parsing %q: %v", to, err)
	}
	return Module{Name: name, From: f, To: v, Indirect: indirect}
}

func TestDisplayName(t *testing.T) {
	direct := mod(t, "golang.org/x/mod", "v0.36.0", "v0.38.0", false)
	if got, want := direct.DisplayName(), "golang.org/x/mod"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	indirect := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true)
	if got, want := indirect.DisplayName(), "golang.org/x/sys (i)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestFormatNameWidth checks that every name occupies the same number of
// visible columns. The marker and the colour escapes must not disturb the
// alignment of the version columns that follow.
func TestFormatNameWidth(t *testing.T) {
	mods := []Module{
		mod(t, "github.com/urfave/cli/v3", "v3.9.0", "v3.10.1", false),
		mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true),
		mod(t, "golang.org/x/mod", "v0.36.0", "v0.38.0", false),
		mod(t, "github.com/mattn/go-isatty", "v0.0.20", "v0.0.24", true),
	}

	width := 0
	for i := range mods {
		width = max(width, len(mods[i].DisplayName()))
	}

	for i := range mods {
		visible := ansi.ReplaceAllString(mods[i].FormatName(width), "")
		if len(visible) != width {
			t.Errorf("%s rendered %d visible columns, want %d (%q)",
				mods[i].Name, len(visible), width, visible)
		}
	}
}

// TestFormatNameNarrowWidth checks that a width smaller than the name does
// not panic on a negative amount of padding.
func TestFormatNameNarrowWidth(t *testing.T) {
	m := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true)
	if got := ansi.ReplaceAllString(m.FormatName(0), ""); got != m.DisplayName() {
		t.Errorf("got %q, want %q", got, m.DisplayName())
	}
}

// TestFormatNameShortens checks that a name too long for the column is
// trimmed at the front, keeping the trailing segments that identify it, and
// that it still fits exactly.
func TestFormatNameShortens(t *testing.T) {
	long := "github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping"
	for _, indirect := range []bool{false, true} {
		m := mod(t, long, "v1.0.0", "v1.0.1", indirect)
		const width = 40
		got := ansi.ReplaceAllString(m.FormatName(width), "")
		if len(got) != width {
			t.Errorf("indirect=%v rendered %d columns, want %d (%q)", indirect, len(got), width, got)
		}
		if !strings.HasPrefix(got, "...") {
			t.Errorf("indirect=%v got %q, want a leading ellipsis", indirect, got)
		}
		if !strings.Contains(got, "resourcemapping") {
			t.Errorf("indirect=%v got %q, want the trailing segment kept", indirect, got)
		}
		// The marker distinguishes an indirect requirement and has to survive.
		if indirect && !strings.HasSuffix(got, indirectMarker) {
			t.Errorf("got %q, want it to end with %q", got, indirectMarker)
		}
	}
}

func TestFormatRequiredBy(t *testing.T) {
	m := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true)
	m.RequiredBy = []string{"example.com/aaa", "example.com/bbb", "example.com/ccc"}

	// Given room for everything, everything is shown.
	full := ansi.ReplaceAllString(m.FormatRequiredBy(200), "")
	if full != "example.com/aaa, example.com/bbb, example.com/ccc" {
		t.Errorf("got %q, want the whole list", full)
	}

	// Given less, the entries that do not fit become a count.
	short := ansi.ReplaceAllString(m.FormatRequiredBy(30), "")
	if !strings.Contains(short, "+2 more") {
		t.Errorf("got %q, want the omitted entries counted", short)
	}
	if !strings.HasPrefix(short, "example.com/aaa") {
		t.Errorf("got %q, want the first entry kept", short)
	}

	// One entry is always shown, even where it cannot fit, since reporting
	// nothing would be less use than reporting too much.
	if got := ansi.ReplaceAllString(m.FormatRequiredBy(1), ""); got == "" {
		t.Error("got nothing, want at least one entry")
	}
}

func TestFormatRequiredByEmpty(t *testing.T) {
	m := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", false)
	if got := m.FormatRequiredBy(80); got != "" {
		t.Errorf("got %q, want nothing when there are no dependents", got)
	}
}

func TestByName(t *testing.T) {
	mods := []Module{
		mod(t, "github.com/mattn/go-isatty", "v0.0.20", "v0.0.24", false),
		mod(t, "github.com/Masterminds/semver/v3", "v3.5.0", "v3.6.0", false),
		mod(t, "github.com/apex/log", "v1.9.0", "v1.9.1", false),
	}
	slices.SortStableFunc(mods, ByName)

	// Sorting by byte value would put every capitalised path first.
	want := []string{
		"github.com/apex/log",
		"github.com/Masterminds/semver/v3",
		"github.com/mattn/go-isatty",
	}
	for i, w := range want {
		if mods[i].Name != w {
			t.Errorf("position %d is %s, want %s", i, mods[i].Name, w)
		}
	}
}

func TestByRisk(t *testing.T) {
	patch := mod(t, "example.com/patch", "v1.2.3", "v1.2.4", false)
	minor := mod(t, "example.com/minor", "v1.2.3", "v1.3.0", false)
	unstable := mod(t, "example.com/unstable", "v0.4.0", "v0.40.0", false)
	major := mod(t, "example.com/major", "v1.2.3", "v2.0.0", false)

	mods := []Module{major, unstable, patch, minor}
	slices.SortStableFunc(mods, ByRisk)

	want := []string{
		"example.com/patch",
		"example.com/minor",
		"example.com/unstable",
		"example.com/major",
	}
	for i, w := range want {
		if mods[i].Name != w {
			t.Errorf("position %d is %s, want %s", i, mods[i].Name, w)
		}
	}
}

// TestByRiskUnstableOrder checks that the size of the jump breaks the tie
// within the sub-v1 tier, where every update shares one risk classification.
func TestByRiskUnstableOrder(t *testing.T) {
	small := mod(t, "example.com/small", "v0.1.14", "v0.1.15", false)
	large := mod(t, "example.com/large", "v0.4.0", "v0.40.0", false)

	mods := []Module{small, large}
	slices.SortStableFunc(mods, ByRisk)

	if mods[0].Name != "example.com/large" {
		t.Errorf("largest jump sorted %s first, want example.com/large", mods[0].Name)
	}
}

func TestByDependents(t *testing.T) {
	few := mod(t, "example.com/few", "v1.0.0", "v1.0.1", false)
	few.RequiredBy = []string{"a"}
	many := mod(t, "example.com/many", "v1.0.0", "v1.0.1", false)
	many.RequiredBy = []string{"a", "b", "c"}
	none := mod(t, "example.com/none", "v1.0.0", "v1.0.1", false)

	mods := []Module{none, few, many}
	slices.SortStableFunc(mods, ByDependents)

	want := []string{"example.com/many", "example.com/few", "example.com/none"}
	for i, w := range want {
		if mods[i].Name != w {
			t.Errorf("position %d is %s, want %s", i, mods[i].Name, w)
		}
	}
}

// TestComparatorsAreTotal checks that each comparator fully determines the
// order, so that a listing does not shuffle between runs.
func TestComparatorsAreTotal(t *testing.T) {
	base := []Module{
		mod(t, "example.com/b", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/a", "v1.0.0", "v1.1.0", true),
		mod(t, "example.com/c", "v0.1.0", "v0.2.0", false),
		mod(t, "example.com/d", "v1.0.0", "v2.0.0", false),
	}

	for _, name := range SortNames() {
		cmp, err := Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}

		first := slices.Clone(base)
		slices.SortStableFunc(first, cmp)

		// Starting from a different arrangement must reach the same order.
		second := slices.Clone(base)
		slices.Reverse(second)
		slices.SortStableFunc(second, cmp)

		for i := range first {
			if first[i].Name != second[i].Name {
				t.Errorf("sort %q is not total: position %d is %s from one input and %s from another",
					name, i, first[i].Name, second[i].Name)
			}
		}
	}
}

func TestLookup(t *testing.T) {
	for _, name := range SortNames() {
		if _, err := Lookup(name); err != nil {
			t.Errorf("Lookup(%q) returned %v, want a comparator", name, err)
		}
	}

	if _, err := Lookup(DefaultSort); err != nil {
		t.Errorf("the default sort %q must resolve: %v", DefaultSort, err)
	}

	err := (error)(nil)
	if _, err = Lookup("bogus"); err == nil {
		t.Fatal("expected an error for an unknown sort")
	}
	// The message needs to say what the accepted values are.
	for _, name := range SortNames() {
		if !regexp.MustCompile(regexp.QuoteMeta(name)).MatchString(err.Error()) {
			t.Errorf("error %q does not mention %q", err, name)
		}
	}
}
