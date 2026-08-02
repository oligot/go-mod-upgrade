package module

import (
	"slices"
	"strings"
	"testing"
)

// modules covering the properties --show selects on.
func filterFixtures(t *testing.T) []Module {
	t.Helper()
	upgradable := mod(t, "example.com/upgradable", "v1.0.0", "v1.1.0", false)
	current := mod(t, "example.com/current", "v1.0.0", "v1.0.0", false)
	vulnerable := mod(t, "example.com/vulnerable", "v1.0.0", "v1.0.0", true)
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	indirect := mod(t, "example.com/indirect", "v1.0.0", "v1.1.0", true)
	return []Module{upgradable, current, vulnerable, indirect}
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
		// An advisory is kept whether or not an upgrade is available.
		{"+cve", []string{"example.com/vulnerable"}},
		// Either property qualifies.
		{"+cve,+delta", []string{
			"example.com/upgradable", "example.com/vulnerable", "example.com/indirect",
		}},
		{"+all", []string{
			"example.com/upgradable", "example.com/current",
			"example.com/vulnerable", "example.com/indirect",
		}},
		// A negated key excludes whatever else was asked for.
		{"+all,-indirect", []string{"example.com/upgradable", "example.com/current"}},
		{"+direct", []string{"example.com/upgradable", "example.com/current"}},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			show, err := ParseFilter(c.spec)
			if err != nil {
				t.Fatalf("ParseShow(%q): %v", c.spec, err)
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
	_, err := ParseFilter("+bogus")
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
	show, err := ParseFilter("+disowned")
	if err != nil {
		t.Fatalf("ParseShow: %v", err)
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

	for _, spec := range []string{"", "+all", "+delta", "+cve,+delta", "+direct", "+disowned"} {
		show, err := ParseFilter(spec)
		if err != nil {
			t.Fatalf("ParseShow(%q): %v", spec, err)
		}
		if got := Apply([]Module{m}, show); len(got) != 0 {
			t.Errorf("--show=%q listed an ignored module", spec)
		}
	}
}
