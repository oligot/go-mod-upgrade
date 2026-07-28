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

// vuln returns a module carrying the given advisory counts.
func vuln(t *testing.T, name string, total, reachable int) Module {
	t.Helper()
	m := mod(t, name, "v1.0.0", "v1.0.1", false)
	m.Vulns = make([]string, total)
	for i := range m.Vulns {
		m.Vulns[i] = "CVE-0000-0000"
	}
	m.Reachable = reachable
	return m
}

// TestByCVE checks the order advisories impose: what the code reaches first,
// since those are the ones that can bite, then how many are merely present.
func TestByCVE(t *testing.T) {
	mods := []Module{
		vuln(t, "example.com/clean", 0, 0),
		vuln(t, "example.com/present", 4, 0),
		vuln(t, "example.com/one-reached", 1, 1),
		vuln(t, "example.com/two-reached", 2, 2),
	}
	sorter, err := ParseSort("+cve")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	slices.SortStableFunc(mods, sorter.Compare)

	want := []string{
		"example.com/two-reached",
		"example.com/one-reached",
		"example.com/present",
		"example.com/clean",
	}
	for i, w := range want {
		if mods[i].Name != w {
			t.Errorf("position %d is %s, want %s", i, mods[i].Name, w)
		}
	}
}

// TestSortDelta checks that a version change is ranked by which part of the
// version moves before how far it moves, so a new major stays ahead of a minor
// that happens to jump further.
func TestSortDelta(t *testing.T) {
	mods := []Module{
		mod(t, "example.com/micro", "v1.2.3", "v1.2.9", false),
		mod(t, "example.com/big-minor", "v1.4.0", "v1.40.0", false),
		mod(t, "example.com/small-minor", "v1.2.0", "v1.3.0", false),
		// One major, against the big minor's thirty-six.
		mod(t, "example.com/major", "v1.2.3", "v2.0.0", false),
		mod(t, "example.com/prerelease", "v1.2.3-rc1", "v1.2.3-rc2", false),
	}
	sorter, err := ParseSort("+delta")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	slices.SortStableFunc(mods, sorter.Compare)

	want := []string{
		// The kind decides first, however small the number.
		"example.com/major",
		// Then distance, within the minor tier.
		"example.com/big-minor",
		"example.com/small-minor",
		"example.com/micro",
		"example.com/prerelease",
	}
	for i, w := range want {
		if mods[i].Name != w {
			t.Errorf("position %d is %s, want %s", i, mods[i].Name, w)
		}
	}
}

// TestSortDeltaKindBeatsDistance pins the rule that which part of the version
// moves outranks how far it moves. Each pair is chosen so that comparing the
// lesser component's distance alone would order it the other way round.
func TestSortDeltaKindBeatsDistance(t *testing.T) {
	cases := []struct {
		name string
		// nearer is the more disruptive change despite the smaller number.
		nearer Module
		wider  Module
	}{
		{
			name:   "one major outranks thirty-nine minors",
			nearer: mod(t, "example.com/wanted", "v1.9.0", "v2.0.0", false),
			wider:  mod(t, "example.com/other", "v1.1.0", "v1.40.0", false),
		},
		{
			name:   "one minor outranks ninety-eight patches",
			nearer: mod(t, "example.com/wanted", "v1.1.0", "v1.2.0", false),
			wider:  mod(t, "example.com/other", "v1.1.0", "v1.1.99", false),
		},
		{
			name:   "any patch outranks a prerelease",
			nearer: mod(t, "example.com/wanted", "v1.1.0", "v1.1.1", false),
			wider:  mod(t, "example.com/other", "v1.1.0-rc1", "v1.1.0-rc99", false),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sorter, err := ParseSort("+delta")
			if err != nil {
				t.Fatalf("ParseSort: %v", err)
			}
			mods := []Module{c.wider, c.nearer}
			slices.SortStableFunc(mods, sorter.Compare)
			if mods[0].Name != "example.com/wanted" {
				t.Errorf("got %s first, want the more disruptive kind of change", mods[0].Name)
			}
		})
	}
}

// TestSortSubV1IsLiteral records that a module below v1 gets no special
// treatment when ordering: the comparison is on the numbers alone.
func TestSortSubV1IsLiteral(t *testing.T) {
	v0 := mod(t, "example.com/v0", "v0.1.0", "v0.2.0", false)
	v1 := mod(t, "example.com/v1", "v1.1.0", "v1.9.0", false)

	mods := []Module{v0, v1}
	sorter, err := ParseSort("+delta")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	slices.SortStableFunc(mods, sorter.Compare)

	// The v1 module moves eight minors against the v0 module's one, so it
	// leads despite v0 being the riskier contract.
	if mods[0].Name != "example.com/v1" {
		t.Errorf("got %s first, want the larger jump", mods[0].Name)
	}
}

func TestParseSortSigns(t *testing.T) {
	a := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	b := mod(t, "example.com/b", "v1.0.0", "v1.0.1", false)

	ascending, err := ParseSort("name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	if ascending.Compare(a, b) >= 0 {
		t.Error("an unsigned key must ascend")
	}

	descending, err := ParseSort("-name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	if descending.Compare(a, b) <= 0 {
		t.Error("a leading - must reverse the key")
	}
}

func TestParseSortChain(t *testing.T) {
	// deps decides first, so the module with more dependants leads even though
	// its name sorts later.
	few := mod(t, "example.com/aaa", "v1.0.0", "v1.0.1", false)
	few.RequiredBy = []string{"x"}
	many := mod(t, "example.com/zzz", "v1.0.0", "v1.0.1", false)
	many.RequiredBy = []string{"x", "y", "z"}

	sorter, err := ParseSort("+deps,+name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	mods := []Module{few, many}
	slices.SortStableFunc(mods, sorter.Compare)
	if mods[0].Name != "example.com/zzz" {
		t.Errorf("got %s first, want the module with more dependants", mods[0].Name)
	}

	// With equal counts the name settles it.
	few.RequiredBy = many.RequiredBy
	mods = []Module{many, few}
	slices.SortStableFunc(mods, sorter.Compare)
	if mods[0].Name != "example.com/aaa" {
		t.Errorf("got %s first, want the name to break the tie", mods[0].Name)
	}
}

// TestParseSortAlwaysTotal checks that every chain ends in a total order, so
// that a listing does not shuffle between runs even when the user's keys
// cannot separate two modules.
func TestParseSortAlwaysTotal(t *testing.T) {
	base := []Module{
		mod(t, "example.com/b", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/a", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/c", "v1.0.0", "v1.0.1", false),
	}

	// None of these keys can tell the modules apart, so only the implied name
	// comparison keeps the order stable.
	for _, spec := range []string{"+cve", "+deps", "+direct", "+delta", "+major"} {
		t.Run(spec, func(t *testing.T) {
			sorter, err := ParseSort(spec)
			if err != nil {
				t.Fatalf("ParseSort: %v", err)
			}
			if !slices.Contains(sorter.Keys, SortName) {
				t.Errorf("keys %v do not end in a name comparison", sorter.Keys)
			}

			first := slices.Clone(base)
			slices.SortStableFunc(first, sorter.Compare)

			second := slices.Clone(base)
			slices.Reverse(second)
			slices.SortStableFunc(second, sorter.Compare)

			for i := range first {
				if first[i].Name != second[i].Name {
					t.Errorf("position %d is %s from one arrangement and %s from another",
						i, first[i].Name, second[i].Name)
				}
			}
		})
	}
}

func TestParseSortDefault(t *testing.T) {
	// An empty value means the default, which leads with advisories and then
	// prefers what the code imports directly.
	sorter, err := ParseSort("")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	if len(sorter.Keys) < 2 || sorter.Keys[0] != SortCVE || sorter.Keys[1] != SortDirect {
		t.Errorf("keys %v do not lead with %q then %q", sorter.Keys, SortCVE, SortDirect)
	}

	if _, err := ParseSort(DefaultSort); err != nil {
		t.Errorf("the default %q must parse: %v", DefaultSort, err)
	}
}

func TestParseSortUnknownKey(t *testing.T) {
	_, err := ParseSort("+bogus")
	if err == nil {
		t.Fatal("expected an error for an unknown key")
	}
	// The message has to say what is accepted.
	for _, key := range SortKeys() {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %q", err, key)
		}
	}
}

// TestByDirect checks that what the code imports directly is offered before
// what it only reaches through something else.
func TestByDirect(t *testing.T) {
	indirect := mod(t, "example.com/aaa", "v1.0.0", "v1.0.1", true)
	direct := mod(t, "example.com/zzz", "v1.0.0", "v1.0.1", false)

	sorter, err := ParseSort("+direct")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	mods := []Module{indirect, direct}
	slices.SortStableFunc(mods, sorter.Compare)
	if mods[0].Name != "example.com/zzz" {
		t.Errorf("got %s first, want the direct requirement", mods[0].Name)
	}

	// The sign has to invert it, since the two cases are the same question.
	reversed, err := ParseSort("-direct")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	mods = []Module{direct, indirect}
	slices.SortStableFunc(mods, reversed.Compare)
	if mods[0].Name != "example.com/aaa" {
		t.Errorf("got %s first, want the indirect requirement", mods[0].Name)
	}
}
