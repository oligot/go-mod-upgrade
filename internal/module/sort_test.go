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

// TestDisplayName checks that the name a caller measures is the module path
// alone. What a module carries beyond that lives in the label column, so it must
// not be counted toward the name's width.
func TestDisplayName(t *testing.T) {
	direct := mod(t, "golang.org/x/mod", "v0.36.0", "v0.38.0", false)
	if got, want := direct.DisplayName(), "golang.org/x/mod"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	indirect := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true)
	if got, want := indirect.DisplayName(), "golang.org/x/sys"; got != want {
		t.Errorf("got %q, want %q: being indirect is a label, not part of the name", got, want)
	}
}

// TestLabelText checks the letters a module carries, and that several appear at
// once: an author can deprecate a module while a reviewer separately marks it
// archived, and an upgrade can fix something elsewhere besides.
//
// The order mirrors the default sort, so the letters read as the priority the
// listing is ordered by.
func TestLabelText(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Module)
		want  string
	}{
		{
			name:  "deprecated",
			setup: func(m *Module) { m.Deprecated = "Use example.com/successor." },
			want:  "D",
		},
		{
			name:  "retracted",
			setup: func(m *Module) { m.Retracted = []string{"Published prematurely"} },
			want:  "R",
		},
		{
			name:  "archived",
			setup: func(m *Module) { m.Archived = "unmaintained since 2018" },
			want:  "A",
		},
		{
			name: "deprecated and archived",
			setup: func(m *Module) {
				m.Deprecated = "Use example.com/successor."
				m.Archived = "unmaintained since 2018"
			},
			want: "DA",
		},
		{
			name:  "resolved by another upgrade",
			setup: func(m *Module) { m.FixedBy = []string{"golang.org/x/term"} },
			want:  "T",
		},
		{
			name:  "fixes something else",
			setup: func(m *Module) { m.Fixes = []string{"golang.org/x/sys"} },
			want:  "F",
		},
		{
			// The group mirrors the default sort, so a fix leads whatever else
			// applies: +fixes comes before +direct in the chain.
			name: "fixes, and required indirectly",
			setup: func(m *Module) {
				m.Fixes = []string{"golang.org/x/sys"}
				m.Indirect = true
			},
			want: "Fi",
		},
		{
			// Every mark at once, in the order the listing is sorted by:
			// fixes, indirect, transitive, then what upstream and a reviewer said.
			name: "the whole group",
			setup: func(m *Module) {
				m.Fixes = []string{"golang.org/x/sys"}
				m.Indirect = true
				m.FixedBy = []string{"golang.org/x/net"}
				m.Deprecated = "Use example.com/successor."
				m.Retracted = []string{"Published prematurely"}
				m.Archived = "unmaintained since 2018"
			},
			want: "FiTDRA",
		},
		{
			name: "every way at once",
			setup: func(m *Module) {
				m.Deprecated = "Use example.com/successor."
				m.Retracted = []string{"Published prematurely"}
				m.Archived = "unmaintained since 2018"
			},
			want: "DRA",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := mod(t, "example.com/m", "v1.0.0", "v1.0.0", false)
			c.setup(&m)
			if got := m.LabelText(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	// A module carrying nothing has no labels, which is what keeps the column
	// out of a listing that needs none.
	clean := mod(t, "example.com/m", "v1.0.0", "v1.0.0", false)
	if got := clean.LabelText(); got != "" {
		t.Errorf("got %q, want no labels", got)
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

// TestFormatNameWidthWithMarkers checks the alignment holds once the disowned
// markers are in play, mixed with indirect ones.
//
// The markers are coloured, so they add escape bytes that len counts but a
// terminal does not. Getting this wrong shifts every version column on the row.
func TestFormatNameWidthWithMarkers(t *testing.T) {
	plain := mod(t, "example.com/plain", "v1.0.0", "v1.1.0", false)

	deprecated := mod(t, "example.com/deprecated", "v1.0.0", "v1.0.0", false)
	deprecated.Deprecated = "Use example.com/successor."

	both := mod(t, "example.com/both", "v1.0.0", "v1.0.0", true)
	both.Retracted = []string{"Published prematurely"}
	both.Archived = "unmaintained"

	every := mod(t, "example.com/every", "v1.0.0", "v1.1.0", true)
	every.Deprecated = "Use example.com/successor."
	every.Retracted = []string{"Published prematurely"}
	every.Archived = "unmaintained"

	mods := []Module{plain, deprecated, both, every}

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
		// The rendering has to agree with what was measured, or the column was
		// sized for something other than what is printed.
		if visible != mods[i].DisplayName()+strings.Repeat(" ", width-len(mods[i].DisplayName())) {
			t.Errorf("%s rendered %q, want the measured name padded",
				mods[i].Name, visible)
		}
	}
}

// TestFormatLabelsWidth checks that the label column occupies its width whether
// or not a module carries labels, since anything after it has to align.
//
// The letters are coloured, so they add escape bytes that len counts but a
// terminal does not.
func TestFormatLabelsWidth(t *testing.T) {
	none := mod(t, "example.com/none", "v1.0.0", "v1.1.0", false)

	one := mod(t, "example.com/one", "v1.0.0", "v1.1.0", true)

	many := mod(t, "example.com/many", "v1.0.0", "v1.1.0", true)
	many.Deprecated = "Use something else."
	many.Archived = "unmaintained"

	mods := []Module{none, one, many}
	width := 0
	for i := range mods {
		width = max(width, len(mods[i].LabelText()))
	}
	if width != 3 {
		t.Fatalf("widest labels = %d, want 3 (iDA)", width)
	}

	for i := range mods {
		visible := ansi.ReplaceAllString(mods[i].FormatLabels(width), "")
		if len(visible) != width {
			t.Errorf("%s rendered %d visible columns, want %d (%q)",
				mods[i].Name, len(visible), width, visible)
		}
		// What is rendered has to agree with what was measured, or the column
		// was sized for something other than what is printed.
		want := mods[i].LabelText() + strings.Repeat(" ", width-len(mods[i].LabelText()))
		if visible != want {
			t.Errorf("%s rendered %q, want %q", mods[i].Name, visible, want)
		}
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
	}
}

func TestFormatRequiredBy(t *testing.T) {
	m := mod(t, "golang.org/x/sys", "v0.42.0", "v0.47.0", true)
	m.RequiredBy = []string{"example.com/aaa", "example.com/bbb", "example.com/ccc"}

	// Given room for everything, everything is shown.
	full := ansi.ReplaceAllString(m.FormatRequiredBy(200), "")
	if full != "example.com/aaa example.com/bbb example.com/ccc" {
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

// TestSortTagsNamedExplicitly checks that asking for the configurations as a sort
// key orders by them ahead of the name, in either direction.
//
// The key is also applied unconditionally, after everything else, to settle two rows
// naming one module. Naming it has to dominate that, or "-tags" would be accepted
// and then quietly ignored.
func TestSortTagsNamedExplicitly(t *testing.T) {
	plain := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	plain.Tags = []string{"*"}
	tagged := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	tagged.Tags = []string{"core && integration"}

	for _, tc := range []struct {
		spec string
		want []string
	}{
		{"+tags", []string{"*"}},
		{"-tags", []string{"core && integration"}},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			sorter, err := ParseSort(tc.spec)
			if err != nil {
				t.Fatalf("ParseSort: %v", err)
			}
			got := []Module{tagged, plain}
			slices.SortStableFunc(got, sorter.Compare)
			if !slices.Equal(got[0].Tags, tc.want) {
				t.Errorf("first row holds %v, want %v", got[0].Tags, tc.want)
			}
		})
	}
}

// TestParseSortSeparatesConfigurations checks that two rows naming one module have
// a decided order, and that they stay together.
//
// A module in the build under two configurations is two rows, and the name cannot
// separate them: it is the same module. Without a tie-break their order is whatever
// the sweep happened to produce, so a listing shuffles between runs and the rows a
// reader means to compare drift apart.
func TestParseSortSeparatesConfigurations(t *testing.T) {
	plain := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	plain.Tags = []string{"*"}
	tagged := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	tagged.Tags = []string{"core && integration"}
	other := mod(t, "example.com/b", "v1.0.0", "v1.0.1", false)

	sorter, err := ParseSort("")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}

	base := []Module{tagged, other, plain}
	first := slices.Clone(base)
	slices.SortStableFunc(first, sorter.Compare)
	second := slices.Clone(base)
	slices.Reverse(second)
	slices.SortStableFunc(second, sorter.Compare)

	for i := range first {
		if !slices.Equal(first[i].Tags, second[i].Tags) {
			t.Fatalf("position %d holds %v from one arrangement and %v from another",
				i, first[i].Tags, second[i].Tags)
		}
	}
	// The two rows for one module are adjacent, which is what lets a reader
	// collapse them by eye.
	if first[0].Name != first[1].Name {
		t.Errorf("rows for one module are not together: %v", names(first))
	}
}

// names renders the module paths of a listing, for reporting a failure.
func names(mods []Module) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.Name)
	}
	return out
}

// TestParseSortAlwaysTotal checks that every chain ends in a total order, so
// that a listing does not shuffle between runs even when the user's keys
// cannot separate two modules.
func TestParseSortAlwaysTotal(t *testing.T) {
	twoConfigs := mod(t, "example.com/a", "v1.0.0", "v1.0.1", false)
	twoConfigs.Tags = []string{"core && integration"}
	base := []Module{
		mod(t, "example.com/b", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/a", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/c", "v1.0.0", "v1.0.1", false),
		// A second row for a module already listed, as one reached under another
		// configuration produces. The name alone cannot separate the two.
		twoConfigs,
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
				if !slices.Equal(first[i].Tags, second[i].Tags) {
					t.Errorf("position %d holds %v from one arrangement and %v from another",
						i, first[i].Tags, second[i].Tags)
				}
			}
		})
	}
}

func TestParseSortDefault(t *testing.T) {
	// An empty value means the default, which leads with the upgrades that
	// resolve an advisory elsewhere, sinks the modules another upgrade already
	// handles, and only then ranks by advisory and how the module is required.
	sorter, err := ParseSort("")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	want := []string{SortFixes, SortCVE, SortDirect, SortTransitive, SortDelta, SortName}
	if !slices.Equal(sorter.Keys, want) {
		t.Errorf("keys %v, want %v", sorter.Keys, want)
	}

	if _, err := ParseSort(DefaultSort); err != nil {
		t.Errorf("the default %q must parse: %v", DefaultSort, err)
	}
}

// TestDefaultSortPutsFixesFirstAndTransitiveLast checks the priority the default
// encodes: the row worth taking leads, and being handled elsewhere demotes a
// module below what is otherwise comparable.
//
// The chain is +fixes,+cve,+direct,+transitive,..., so an advisory still outranks
// a module with none even when something else will resolve it. What transitive
// decides is the order among modules the earlier keys leave equal.
func TestDefaultSortPutsFixesFirstAndTransitiveLast(t *testing.T) {
	// A module with a reachable advisory, needing direct action.
	vulnerable := mod(t, "example.com/vulnerable", "v1.0.0", "v1.1.0", false)
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	vulnerable.Reachable = 1

	// The upgrade that would clear an advisory somewhere else.
	fixer := mod(t, "example.com/fixer", "v1.0.0", "v2.0.0", false)
	fixer.Fixes = []string{"example.com/resolved"}

	// Also carrying a reachable advisory, but one the fixer resolves.
	resolved := mod(t, "example.com/resolved", "v1.0.0", "v1.1.0", false)
	resolved.Vulns = []string{"CVE-0000-0002"}
	resolved.Reachable = 1
	resolved.FixedBy = []string{"example.com/fixer"}

	ordinary := mod(t, "example.com/ordinary", "v1.0.0", "v1.0.1", false)

	got := []Module{resolved, vulnerable, ordinary, fixer}
	sorter, err := ParseSort("")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	slices.SortStableFunc(got, sorter.Compare)

	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	want := []string{
		// Leads: taking it clears a finding elsewhere.
		"example.com/fixer",
		// Both carry a reachable advisory, so +cve puts them ahead of the
		// module with none; +transitive then settles the two between themselves.
		"example.com/vulnerable",
		"example.com/resolved",
		"example.com/ordinary",
	}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

// TestSortByFixesRanksByCount checks that an upgrade clearing more advisories
// leads, since fixing three modules is worth more than fixing one.
func TestSortByFixesRanksByCount(t *testing.T) {
	one := mod(t, "example.com/one", "v1.0.0", "v1.1.0", false)
	one.Fixes = []string{"example.com/a"}

	three := mod(t, "example.com/three", "v1.0.0", "v1.1.0", false)
	three.Fixes = []string{"example.com/a", "example.com/b", "example.com/c"}

	none := mod(t, "example.com/none", "v1.0.0", "v1.1.0", false)

	sorter, err := ParseSort("+fixes,+name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	got := []Module{none, one, three}
	slices.SortStableFunc(got, sorter.Compare)

	want := []string{"example.com/three", "example.com/one", "example.com/none"}
	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
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

// TestSortByDisowned checks that the modules given up on lead, since no upgrade
// resolves being abandoned and they need a decision rather than a bump.
func TestSortByDisowned(t *testing.T) {
	fine := mod(t, "example.com/fine", "v1.0.0", "v1.1.0", false)
	deprecated := mod(t, "example.com/deprecated", "v1.0.0", "v1.1.0", false)
	deprecated.Deprecated = "Use example.com/successor."
	archived := mod(t, "example.com/archived", "v1.0.0", "v1.1.0", false)
	archived.Archived = "unmaintained"

	sorter, err := ParseSort("+disowned,+name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	got := []Module{fine, deprecated, archived}
	slices.SortStableFunc(got, sorter.Compare)

	want := []string{
		"example.com/archived", "example.com/deprecated", "example.com/fine",
	}
	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}

	// Reversed, the ordinary modules lead instead.
	rev, err := ParseSort("-disowned,+name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	slices.SortStableFunc(got, rev.Compare)
	if got[0].Name != "example.com/fine" {
		t.Errorf("reversed, got %q first, want the unmarked module", got[0].Name)
	}
}

// TestSortByTransitive checks that a module another upgrade would resolve sorts
// last, since it needs no direct action.
//
// This key runs the opposite way from the others: a leading "+" leads with what
// is most pressing everywhere else, and here the marked module is the least
// pressing thing in the listing.
func TestSortByTransitive(t *testing.T) {
	needsWork := mod(t, "example.com/needs-work", "v1.0.0", "v1.1.0", false)
	resolved := mod(t, "example.com/resolved", "v1.0.0", "v1.1.0", false)
	resolved.FixedBy = []string{"example.com/dependent"}

	sorter, err := ParseSort("+transitive,+name")
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	got := []Module{resolved, needsWork}
	slices.SortStableFunc(got, sorter.Compare)

	if got[0].Name != "example.com/needs-work" {
		t.Errorf("got %q first, want the module needing action", got[0].Name)
	}
	if got[1].Name != "example.com/resolved" {
		t.Errorf("got %q last, want the transitively resolved module", got[1].Name)
	}
}

// TestFilterTransitive checks the filter, which is most useful negated: asking for
// everything except what another upgrade already handles.
func TestFilterTransitive(t *testing.T) {
	needsWork := mod(t, "example.com/needs-work", "v1.0.0", "v1.1.0", false)
	resolved := mod(t, "example.com/resolved", "v1.0.0", "v1.1.0", false)
	resolved.FixedBy = []string{"example.com/dependent"}
	all := []Module{needsWork, resolved}

	cases := []struct {
		spec string
		want []string
	}{
		{"transitive", []string{"example.com/resolved"}},
		{"+all,-transitive", []string{"example.com/needs-work"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			show, err := ParseFilter(c.spec, DefaultFilters())
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", c.spec, err)
			}
			var got []string
			for _, m := range Apply(all, show) {
				got = append(got, m.Name)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestJoinPaths checks that paths are separated by a single space and quoted only
// when a quote changes what the value is.
//
// A module path never needs quoting, and quotes in a width-constrained column
// cost two characters an entry for nothing.
func TestJoinPaths(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  string
	}{
		{
			name:  "ordinary paths are bare",
			paths: []string{"github.com/fatih/color", "golang.org/x/sys"},
			want:  "github.com/fatih/color golang.org/x/sys",
		},
		{
			// The workspace root, which is what a member with no subdirectory is.
			name:  "the workspace root",
			paths: []string{".", "cmd/osgen"},
			want:  ". cmd/osgen",
		},
		{
			// A space would run one entry into the next, so it is quoted.
			name:  "a path holding a space",
			paths: []string{"example.com/a b", "example.com/c"},
			want:  `"example.com/a b" example.com/c`,
		},
		{
			name:  "a path holding a quote",
			paths: []string{`example.com/a"b`},
			want:  `"example.com/a\"b"`,
		},
		{
			name:  "nothing at all",
			paths: nil,
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := JoinPaths(c.paths); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
