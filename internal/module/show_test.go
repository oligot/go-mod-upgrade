package module

import (
	"slices"
	"strings"
	"testing"
)

// modules covering the properties --show selects on.
func showFixtures(t *testing.T) []Module {
	t.Helper()
	upgradable := mod(t, "example.com/upgradable", "v1.0.0", "v1.1.0", false)
	current := mod(t, "example.com/current", "v1.0.0", "v1.0.0", false)
	vulnerable := mod(t, "example.com/vulnerable", "v1.0.0", "v1.0.0", true)
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	indirect := mod(t, "example.com/indirect", "v1.0.0", "v1.1.0", true)
	return []Module{upgradable, current, vulnerable, indirect}
}

func TestShowFilters(t *testing.T) {
	all := showFixtures(t)
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
			show, err := ParseShow(c.spec)
			if err != nil {
				t.Fatalf("ParseShow(%q): %v", c.spec, err)
			}
			var got []string
			for _, m := range Filter(all, show) {
				got = append(got, m.Name)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseShowUnknownKey(t *testing.T) {
	_, err := ParseShow("+bogus")
	if err == nil {
		t.Fatal("expected an error for an unknown key")
	}
	for _, key := range ShowKeys() {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %q", err, key)
		}
	}
}
