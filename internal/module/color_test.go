package module

import (
	"regexp"
	"strings"
	"testing"
)

// escapes matches an ANSI sequence, so a test can compare what is rendered
// against what is visible.
var escapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestSetColorsOverrides(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	if err := SetColors("from=none,vuln=bold+red"); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	// A role set to none renders without any sequence at all.
	if got := paint(RoleFrom)("v1.0.0"); got != "v1.0.0" {
		t.Errorf("from = %q, want it uncoloured", got)
	}
	// A role given attributes renders with them.
	if got := paint(RoleVuln)("CVE-1"); !strings.Contains(got, "\x1b[") {
		t.Errorf("vuln = %q, want it coloured", got)
	}
	// Roles the spec did not mention keep their defaults.
	if got := paint(RoleRequiredBy)("x"); !strings.Contains(got, "\x1b[") {
		t.Errorf("required-by = %q, want the default colour", got)
	}
}

func TestSetColorsEmpty(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	// No spec means the defaults, which must still colour an advisory.
	if err := SetColors(""); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	if got := paint(RoleVulnReachable)("CVE-1"); !strings.Contains(got, "\x1b[") {
		t.Errorf("vuln-reachable = %q, want the default colour", got)
	}
}

func TestSetColorsRejects(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	cases := []struct {
		name string
		spec string
		says string
	}{
		{"unknown role", "bogus=red", "bogus"},
		{"unknown attribute", "vuln=plaid", "plaid"},
		{"not a pair", "justthis", "justthis"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := SetColors(c.spec)
			if err == nil {
				t.Fatalf("SetColors(%q) succeeded, want an error", c.spec)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("error %q does not mention %q", err, c.says)
			}
		})
	}
}

// TestSetColorsRejectionLeavesPaletteIntact checks that a bad spec does not
// half-apply, since the run continues only if the palette is refused whole.
func TestSetColorsRejectionLeavesPaletteIntact(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	before := paint(RoleFrom)("v1.0.0")
	if err := SetColors("from=none,bogus=red"); err == nil {
		t.Fatal("expected an error")
	}
	if after := paint(RoleFrom)("v1.0.0"); after != before {
		t.Errorf("from became %q, want it left at %q", after, before)
	}
}

// TestFormatToColoursFromFirstChange checks the rule the version column
// follows: colour the leftmost component that moves and everything after it,
// so the extent of the change is visible at a glance.
func TestFormatToColoursFromFirstChange(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		// plain is the leading text that keeps the default colour.
		plain string
		// coloured is the remainder, which carries the change colour.
		coloured string
	}{
		{"major moves", "v1.2.3", "v2.0.0", "", "2.0.0"},
		{"minor moves", "v0.11.2", "v0.12.7", "0.", "12.7"},
		{"micro moves", "v1.24.0", "v1.24.6", "1.24.", "6"},
		{"prerelease moves", "v0.2.2-rc1", "v0.2.2-rc2", "0.2.2", "-rc2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := mod(t, "example.com/m", c.from, c.to, false)
			out := m.FormatTo(0)

			// The whole version has to survive, colour or not.
			if got, want := escapes.ReplaceAllString(out, ""), c.plain+c.coloured; got != want {
				t.Errorf("rendered %q, want %q", got, want)
			}
			// The change has to be coloured the same in both columns, since it
			// is one change seen twice.
			from := mod(t, "example.com/m", c.from, c.to, false)
			if got, want := changeCodes(from.FormatFrom(0)), changeCodes(out); got != want {
				t.Errorf("the change reads %v in the current version and %v in the new one", got, want)
			}
		})
	}
}

// TestFormatToRolePerComponent checks that each kind of change is coloured
// differently, so the kind can be told apart at a glance and not only the
// extent.
func TestFormatToRolePerComponent(t *testing.T) {
	seen := map[string]string{}
	for _, c := range []struct {
		role string
		from string
		to   string
	}{
		{RoleToMajor, "v1.2.3", "v2.0.0"},
		{RoleToMinor, "v1.2.3", "v1.3.0"},
		{RoleToMicro, "v1.2.3", "v1.2.4"},
		{RoleToPrerelease, "v1.2.3-rc1", "v1.2.3-rc2"},
	} {
		m := mod(t, "example.com/m", c.from, c.to, false)
		if got := m.changedRole(); got != c.role {
			t.Errorf("%s -> %s took role %q, want %q", c.from, c.to, got, c.role)
		}
		codes := strings.Join(escapes.FindAllString(m.FormatTo(0), -1), "")
		if prev, ok := seen[codes]; ok {
			t.Errorf("role %q renders the same as %q, want them distinguishable", c.role, prev)
		}
		seen[codes] = c.role
	}
}

func TestSetColorsSchemes(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	dark := func() string {
		if err := SetColors(SchemeDark); err != nil {
			t.Fatalf("SetColors: %v", err)
		}
		return paint(RoleToMinor)("1.2.3")
	}()
	light := func() string {
		if err := SetColors(SchemeLight); err != nil {
			t.Fatalf("SetColors: %v", err)
		}
		return paint(RoleToMinor)("1.2.3")
	}()
	if dark == light {
		t.Errorf("both schemes render %q, want them to differ", dark)
	}

	// The default is the dark scheme, since a terminal cannot be asked what
	// its background is.
	if err := SetColors(""); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	if got := paint(RoleToMinor)("1.2.3"); got != dark {
		t.Errorf("the default renders %q, want the dark scheme's %q", got, dark)
	}
}

// TestSetColorsSchemeThenOverride checks that a named scheme can be adjusted,
// rather than having to be spelled out in full to change one role.
func TestSetColorsSchemeThenOverride(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	if err := SetColors("light,vuln=none"); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	// The named role takes the override.
	if got := paint(RoleVuln)("CVE-1"); got != "CVE-1" {
		t.Errorf("vuln = %q, want it uncoloured", got)
	}
	// The rest keeps the scheme rather than the default.
	if err := SetColors(SchemeLight); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	want := paint(RoleToMinor)("1.2.3")
	if err := SetColors("light,vuln=none"); err != nil {
		t.Fatalf("SetColors: %v", err)
	}
	if got := paint(RoleToMinor)("1.2.3"); got != want {
		t.Errorf("to-minor = %q, want the light scheme's %q", got, want)
	}
}

func TestSetColorsUnknownScheme(t *testing.T) {
	t.Cleanup(func() { active = defaults })

	err := SetColors("chartreuse")
	if err == nil {
		t.Fatal("expected an error for an unknown scheme")
	}
	for _, name := range SchemeNames() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not mention %q", err, name)
		}
	}
}

// changeCodes returns the sequences colouring the part of a version that
// changes, which is whatever follows the prefix the column recedes in.
func changeCodes(rendered string) string {
	found := escapes.FindAllString(rendered, -1)
	if len(found) < 3 {
		return ""
	}
	// The first pair colours the unchanged prefix; the rest colour the change.
	return strings.Join(found[2:], "")
}
