package module

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVulnKeysPartitionTheAdvisories pins that vuln_reachable and vuln_present
// divide the advisories rather than overlapping.
//
// A row carries at most one of V and P, so the label column says which of the two
// claims holds rather than stacking both. Together they keep every module carrying
// an advisory, which is what makes the pair a partition rather than two views with
// a gap between them.
func TestVulnKeysPartitionTheAdvisories(t *testing.T) {
	reached := mod(t, "example.com/reached", "v1.0.0", "v1.0.0", false)
	reached.Vulns = []string{"CVE-0000-0001"}
	reached.Reachable = 1

	present := mod(t, "example.com/present", "v1.0.0", "v1.0.0", false)
	present.Vulns = []string{"CVE-0000-0002"}

	clean := mod(t, "example.com/clean", "v1.0.0", "v1.0.0", false)

	tests := []struct {
		spec string
		want []string
	}{
		{FilterVulnReachable, []string{"example.com/reached"}},
		// Disjoint: the reached module is not also present-only.
		{FilterVulnPresent, []string{"example.com/present"}},
		// "vuln" is the short way to say reachable.
		{FilterVuln, []string{"example.com/reached"}},
		// Exhaustive: together they keep every advisory there is.
		{FilterVulnReachable + "," + FilterVulnPresent, []string{
			"example.com/reached", "example.com/present",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, DefaultFilters())
			require.NoError(t, err)
			var got []string
			for _, m := range Apply([]Module{reached, present, clean}, f) {
				got = append(got, m.Name)
			}
			require.Equal(t, tc.want, got)
		})
	}

	// And the letters do not stack: a reached module prints V alone.
	require.Equal(t, vulnReachableLabel, reached.LabelText())
	require.Equal(t, vulnPresentLabel, present.LabelText())
}

// TestDefaultListsReachedAdvisoriesWithoutAnUpgrade pins what the default keeps
// beyond the modules with an upgrade waiting.
//
// A reached advisory with no newer version is the row the delta-only default withheld:
// there is nothing to upgrade to, so the one key that used to select would drop it, and
// the listing would report a tree whose vulnerable code runs as a clean one. Reaching it
// is the reason to say so, not the availability of a fix.
//
// The unreached advisory stays out, the default naming the reached sense alone. Asking
// for both senses is what lists every advisory there is.
func TestDefaultListsReachedAdvisoriesWithoutAnUpgrade(t *testing.T) {
	// Current, so FilterDelta keeps neither.
	stuck := mod(t, "example.com/stuck", "v1.0.0", "v1.0.0", false)
	stuck.Vulns = []string{"CVE-0000-0003"}
	stuck.Reachable = 1

	unreached := mod(t, "example.com/unreached", "v1.0.0", "v1.0.0", false)
	unreached.Vulns = []string{"CVE-0000-0004"}

	upgradable := mod(t, "example.com/upgradable", "v1.0.0", "v1.1.0", false)
	clean := mod(t, "example.com/clean", "v1.0.0", "v1.0.0", false)
	// Indirect and upgradable. Every upgradable module in a real workspace was one of
	// these, and a default that listed none of them read as "nothing to do".
	buried := mod(t, "example.com/buried", "v1.0.0", "v1.1.0", true)
	// Indirect and already current, which is most of a build list: the reason the
	// default intersects rather than naming the indirect key alone.
	settled := mod(t, "example.com/settled", "v1.0.0", "v1.0.0", true)
	all := []Module{stuck, unreached, upgradable, clean, buried, settled}

	tests := []struct {
		spec string
		want []string
	}{{
		// The default: an upgrade available, or vulnerable code reached. An indirect
		// requirement is still a version this project ships, so an upgrade to one is
		// still an upgrade to take -- and the indirect module that is current is not
		// listed beside it.
		spec: "",
		want: []string{"example.com/stuck", "example.com/upgradable", "example.com/buried"},
	}, {
		// Dropping the advisories from the default leaves what it used to keep.
		spec: "-" + FilterVulnReachable,
		want: []string{"example.com/upgradable", "example.com/buried"},
	}, {
		// Added to the default, the unreached sense brings the last advisory in.
		spec: "+" + FilterVulnPresent,
		want: []string{
			"example.com/stuck", "example.com/unreached", "example.com/upgradable",
			"example.com/buried",
		},
	}, {
		// Dropping the indirect requirements from the default leaves the direct ones,
		// which is what the default used to keep before it widened.
		spec: "-" + FilterIndirect,
		want: []string{"example.com/stuck", "example.com/upgradable"},
	}}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, DefaultFilters())
			require.NoError(t, err)
			var got []string
			for _, m := range Apply(all, f) {
				got = append(got, m.Name)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

// downgradeFixtures covers the directions an available version can take against the
// one installed.
func downgradeFixtures(t *testing.T) []Module {
	t.Helper()
	back := mod(t, "example.com/back", "v1.43.3", "v1.43.2", false)
	forward := mod(t, "example.com/forward", "v1.0.0", "v1.1.0", false)
	current := mod(t, "example.com/current", "v1.0.0", "v1.0.0", false)
	// Nothing was learned about this one, so it stands where it is.
	unchecked := mod(t, "example.com/unchecked", "v1.0.0", "v1.0.0", false)
	unchecked.Unchecked = true
	// Unchecked AND standing above the version on offer, which is what a workspace row
	// looks like after PerRequirement: one To is carried across every version the
	// members require, so a member requiring more than the merged version has a To
	// below its From. Nothing was checked, so nothing went backwards.
	behind := mod(t, "example.com/behind", "v1.1.0", "v1.0.0", false)
	behind.Unchecked = true
	// Deprecated as well as backwards, which is what puts "d" and "D" in one cell.
	both := mod(t, "example.com/both", "v2.0.0", "v1.9.0", false)
	both.Deprecated = "use something else"
	return []Module{back, forward, current, unchecked, behind, both}
}

// TestDowngradeSelectsABackwardsVersion checks which rows the downgrade key keeps.
//
// FilterDelta keeps whatever differs from what is installed, in either direction, so
// a proxy offering an older version had it listed as an upgrade to take. The row is
// marked rather than withheld: something has gone backwards upstream, most likely a
// retraction or a republished tag, and that is worth seeing. A key of its own is what
// lets a listing ask for the upgrades alone.
func TestDowngradeSelectsABackwardsVersion(t *testing.T) {
	all := downgradeFixtures(t)

	tests := []struct {
		name string
		spec string
		want []string
	}{{
		// The key selects the backwards rows and nothing else.
		name: "named alone",
		spec: FilterDowngrade,
		want: []string{"example.com/back", "example.com/both"},
	}, {
		// A downgrade differs from what is installed, so the delta key keeps it. The
		// mark is what tells it apart from an upgrade, not its absence from the listing.
		name: "kept by delta",
		spec: FilterDelta,
		want: []string{
			"example.com/back", "example.com/forward", "example.com/unchecked",
			"example.com/behind", "example.com/both",
		},
	}, {
		// And it can be dropped, which is the reason to give it a key.
		name: "dropped from the default",
		spec: "-" + FilterDowngrade,
		want: []string{"example.com/forward", "example.com/unchecked", "example.com/behind"},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, DefaultFilters())
			require.NoError(t, err)
			var got []string
			for _, m := range Apply(all, f) {
				got = append(got, m.Name)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

// TestDowngradeMarksABackwardsVersion checks the letter each row prints.
//
// Spelled out rather than compared to downgradeLabel, which would pin nothing: "d"
// beside the "D" of deprecation is the choice, so the choice is what is asserted. The
// two can appear together, a module being both, which is why the legend has to
// distinguish them.
func TestDowngradeMarksABackwardsVersion(t *testing.T) {
	all := downgradeFixtures(t)

	tests := []struct {
		name string
		want string
		why  string
	}{
		{name: "example.com/back", want: "d", why: "a backwards version is marked"},
		{name: "example.com/forward", want: "", why: "an upgrade is not marked"},
		{name: "example.com/current", want: "", why: "a current module is not marked"},
		// "?" alone: the row says nothing was learned, and an absent answer is not a
		// backwards one.
		{name: "example.com/unchecked", want: "?", why: "an absent answer is not a backwards one"},
		// The case the guard exists for: standing above what is on offer, having never
		// been checked. Marking this would report an unexamined module as having gone
		// backwards upstream.
		{name: "example.com/behind", want: "?", why: "an unchecked module has not gone backwards"},
		// In the order labelSpecs lists them, which is the order a row prints.
		{name: "example.com/both", want: "dD", why: "a module can be both"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := slices.IndexFunc(all, func(m Module) bool { return m.Name == tc.name })
			require.GreaterOrEqual(t, i, 0, "no such fixture")
			require.Equal(t, tc.want, all[i].LabelText(), tc.why)
		})
	}

	// The key a reader would look the letter up by, so a row says which selector kept it.
	require.Equal(t, "d", LabelLetter(FilterDowngrade))

	// The legend distinguishes the two, "d" being no use beside "D" unexplained.
	i := slices.IndexFunc(all, func(m Module) bool { return m.Name == "example.com/both" })
	legend := escapes.ReplaceAllString(Legend([]Module{all[i]}), "")
	require.Contains(t, legend, "older than the one installed")
	require.Contains(t, legend, "deprecated by its author")
}

// modules covering the properties --filter selects on.
func filterFixtures(t *testing.T) []Module {
	t.Helper()
	upgradable := mod(t, "example.com/upgradable", "v1.0.0", "v1.1.0", false)
	current := mod(t, "example.com/current", "v1.0.0", "v1.0.0", false)
	vulnerable := mod(t, "example.com/vulnerable", "v1.0.0", "v1.0.0", true)
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	indirect := mod(t, "example.com/indirect", "v1.0.0", "v1.1.0", true)
	return []Module{upgradable, current, vulnerable, indirect}
}

// TestParseFilterAdjustsTheDefault checks that a signed key changes what the default
// keeps rather than replacing it, and that an unsigned one replaces.
//
// Without this, "+cooldown" would mean "only the modules cooling down" -- the
// opposite of the "the usual, plus these" a reader writes it expecting. --columns
// already works this way, and a caller has no reason to hold two rules.
func TestParseFilterAdjustsTheDefault(t *testing.T) {
	base := []string{FilterDelta}
	for _, tc := range []struct {
		spec string
		want []string
	}{{
		// Signed: the default stands and the key is added to it.
		spec: "+vuln_present",
		want: []string{"example.com/upgradable", "example.com/vulnerable", "example.com/indirect"},
	}, {
		// Unsigned: the default is gone, and only what was named applies.
		spec: "vuln_present",
		want: []string{"example.com/vulnerable"},
	}, {
		// "vuln" resolves to vuln_reachable, which this fixture's advisory is not:
		// it carries a finding nothing calls, so the reached key keeps nothing.
		spec: "vuln",
		want: nil,
	}, {
		// Subtracting from the default, which needs the default to still be there.
		spec: "-indirect",
		want: []string{"example.com/upgradable"},
	}, {
		spec: "",
		want: []string{"example.com/upgradable", "example.com/indirect"},
	}} {
		t.Run(tc.spec, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, base)
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.spec, err)
			}
			var got []string
			for _, m := range Apply(filterFixtures(t), f) {
				got = append(got, m.Name)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseFilterRejectsMixedForms checks that naming a set and adjusting one in the
// same value is refused rather than guessed at, as --columns refuses it.
func TestParseFilterRejectsMixedForms(t *testing.T) {
	if _, err := ParseFilter("vuln_present,+delta", []string{FilterDelta}); err == nil {
		t.Error("expected an error for a value that both names and adjusts")
	}
}

// TestParseFilterIntersects checks that keys joined with "&" keep only the modules
// carrying every one of them, where a comma keeps the modules carrying any.
//
// Two properties in one chain used to mean either, so "indirect,delta" and
// "+indirect" both widened a listing to every indirect module rather than narrowing
// it to the indirect ones with an upgrade. There was no way to ask for the
// intersection, which is the question a reader asks of two properties most often:
// the modules that are both.
func TestParseFilterIntersects(t *testing.T) {
	// An upgrade and indirect; an upgrade and direct; indirect and current. Only the
	// first carries both properties.
	indirectUpgrade := mod(t, "example.com/indirect-upgrade", "v1.0.0", "v1.1.0", true)
	directUpgrade := mod(t, "example.com/direct-upgrade", "v1.0.0", "v1.1.0", false)
	indirectCurrent := mod(t, "example.com/indirect-current", "v1.0.0", "v1.0.0", true)
	all := []Module{indirectUpgrade, directUpgrade, indirectCurrent}

	for _, tc := range []struct {
		spec string
		want []string
	}{{
		// The question that had no spelling: indirect AND upgradable.
		spec: "indirect&delta",
		want: []string{"example.com/indirect-upgrade"},
	}, {
		// Order does not matter, an intersection being symmetric.
		spec: "delta&indirect",
		want: []string{"example.com/indirect-upgrade"},
	}, {
		// A comma still keeps either, so the widening spelling is unchanged.
		spec: "indirect,delta",
		want: []string{
			"example.com/indirect-upgrade", "example.com/direct-upgrade",
			"example.com/indirect-current",
		},
	}, {
		// An intersection of one key is that key, there being nothing to intersect.
		spec: "indirect",
		want: []string{"example.com/indirect-upgrade", "example.com/indirect-current"},
	}, {
		// Both forms in one chain: either "direct alone" or "indirect and upgradable".
		spec: "direct,indirect&delta",
		want: []string{"example.com/indirect-upgrade", "example.com/direct-upgrade"},
	}, {
		// Nothing carries both, so nothing is kept rather than everything.
		spec: "direct&indirect",
		want: nil,
	}} {
		t.Run(tc.spec, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, DefaultFilters())
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.spec, err)
			}
			var got []string
			for _, m := range Apply(all, f) {
				got = append(got, m.Name)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseFilterIntersectionExcludes checks that a negated intersection drops the
// modules carrying every one of its keys, and keeps the ones carrying only some.
//
// A drop outranks a keep whatever the chain's order, which an intersection does not
// change: what it changes is which rows the drop matches.
func TestParseFilterIntersectionExcludes(t *testing.T) {
	indirectUpgrade := mod(t, "example.com/indirect-upgrade", "v1.0.0", "v1.1.0", true)
	directUpgrade := mod(t, "example.com/direct-upgrade", "v1.0.0", "v1.1.0", false)
	indirectCurrent := mod(t, "example.com/indirect-current", "v1.0.0", "v1.0.0", true)
	all := []Module{indirectUpgrade, directUpgrade, indirectCurrent}

	f, err := ParseFilter("+all,-indirect&delta", DefaultFilters())
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	var got []string
	for _, m := range Apply(all, f) {
		got = append(got, m.Name)
	}
	// The indirect module with an upgrade is dropped; the one that is merely indirect
	// is not, carrying only one of the two keys.
	want := []string{"example.com/direct-upgrade", "example.com/indirect-current"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseFilterRejectsUnknownIntersected checks that a key naming no label is
// refused inside an intersection too, rather than silently keeping nothing.
func TestParseFilterRejectsUnknownIntersected(t *testing.T) {
	if _, err := ParseFilter("indirect&bogus", DefaultFilters()); err == nil {
		t.Error("expected an error for an unknown key in an intersection")
	}
}

func TestFilterKeeps(t *testing.T) {
	all := filterFixtures(t)
	cases := []struct {
		spec string
		want []string
	}{
		// The default keeps what the tool has always listed.
		{"", []string{"example.com/upgradable", "example.com/indirect"}},
		{"+delta", []string{"example.com/upgradable", "example.com/indirect"}},
		// Named alone, an advisory is kept whether or not an upgrade is available.
		{"vuln_present", []string{"example.com/vulnerable"}},
		// Either property qualifies.
		{"vuln_present,delta", []string{
			"example.com/upgradable", "example.com/vulnerable", "example.com/indirect",
		}},
		{"all", []string{
			"example.com/upgradable", "example.com/current",
			"example.com/vulnerable", "example.com/indirect",
		}},
		// A negated key excludes whatever else was asked for.
		{"+all,-indirect", []string{"example.com/upgradable", "example.com/current"}},
		{"direct", []string{"example.com/upgradable", "example.com/current"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			show, err := ParseFilter(c.spec, []string{FilterDelta})
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

func TestParseFilterUnknownKey(t *testing.T) {
	_, err := ParseFilter("+bogus", DefaultFilters())
	if err == nil {
		t.Fatal("expected an error for an unknown key")
	}
	for _, key := range FilterKeys() {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %q", err, key)
		}
	}
}

// TestFilterDisownedCoversEveryWay checks that +disowned keeps a module given up
// on however that was established, since a reader wants the abandoned ones
// rather than one flavour of abandonment.
func TestFilterDisownedCoversEveryWay(t *testing.T) {
	deprecated := mod(t, "example.com/deprecated", "v1.0.0", "v1.0.0", false)
	deprecated.Deprecated = "Use example.com/successor instead."
	retracted := mod(t, "example.com/retracted", "v1.0.0", "v1.1.0", false)
	retracted.Retracted = []string{"Published prematurely"}
	archived := mod(t, "example.com/archived", "v1.0.0", "v1.0.0", false)
	archived.Archived = "unmaintained since 2018"
	// Current, permitted, and nothing said about it.
	fine := mod(t, "example.com/fine", "v1.0.0", "v1.0.0", false)

	all := []Module{deprecated, retracted, archived, fine}
	show, err := ParseFilter("disowned", DefaultFilters())
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}

	var got []string
	for _, m := range Apply(all, show) {
		got = append(got, m.Name)
	}
	want := []string{
		"example.com/deprecated", "example.com/retracted", "example.com/archived",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestFilterNeverListsIgnored checks that a module withheld by --ignore stays out
// of the listing however wide the filter, since asking for everything is not
// asking for what was declined.
func TestFilterNeverListsIgnored(t *testing.T) {
	m := mod(t, "example.com/ignored", "v1.0.0", "v1.1.0", false)
	m.Ignored = true

	for _, spec := range []string{"", "all", "+delta", "vuln_present,delta", "direct", "+disowned"} {
		show, err := ParseFilter(spec, DefaultFilters())
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", spec, err)
		}
		if got := Apply([]Module{m}, show); len(got) != 0 {
			t.Errorf("--filter=%q listed an ignored module", spec)
		}
	}
}

// TestFilterKeysListsEveryFilter checks that the keys named in help text are the keys the
// parser accepts.
//
// A key that works but is not listed cannot be discovered: it is absent from --help and
// from the error naming what is valid, so the only way to find it is to read the source.
// FilterCooldown shipped that way.
func TestFilterKeysListsEveryFilter(t *testing.T) {
	keys := FilterKeys()
	for key := range filters {
		if !slices.Contains(keys, key) {
			t.Errorf("filter %q is accepted but missing from FilterKeys()", key)
		}
	}
	// And nothing is advertised that the parser would reject.
	for _, key := range keys {
		if _, ok := filters[key]; !ok {
			t.Errorf("FilterKeys() names %q, which is not a filter", key)
		}
	}
	// Every key of every default term, since a base is not validated the way a flag
	// value is: an unknown key there reaches Keep with no predicate behind it, which
	// panicked rather than reporting anything. Written here rather than typed, so the
	// check belongs in the suite instead of the parser.
	for _, entry := range DefaultFilters() {
		for _, key := range baseKeys(entry) {
			if _, ok := filters[key]; !ok {
				t.Errorf("DefaultFilters() names %q in %q, which is not a filter", key, entry)
			}
		}
	}
}
