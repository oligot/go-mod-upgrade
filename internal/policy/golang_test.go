package policy

import (
	"strings"
	"testing"
)

// TestParseReleasesRejectsNothing checks that an empty or unusable answer is an error
// rather than an empty window.
//
// An empty window would permit everything, so a policy asking about Go versions would
// silently stop asking -- the failure mode a security setting must not have.
func TestParseReleasesRejectsNothing(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty list", `[]`},
		{"nothing stable", `[{"version": "go1.27rc1", "stable": false}]`},
		{"not json", `<html>503</html>`},
		{"unreadable versions", `[{"version": "tip", "stable": true}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseReleases(false, []byte(tc.body)); err == nil {
				t.Errorf("ParseReleases() = %v, want an error", got)
			}
		})
	}
}

// TestChannelCeiling works out the newest version a project may declare, from offsets
// against the current release.
//
// The offsets make the algebra explicit rather than hiding it in a count. Each applies to
// its own component of the current release, so a project can bound how far behind it stays
// in minors separately from patches -- and the components below an offset one clamp to that
// release's newest, since "two minors back" means the newest of that minor rather than a
// patch level carried across from today.
func TestChannelCeiling(t *testing.T) {
	// Newest first, as go.dev reports them.
	published := []string{"1.26.5", "1.26.4", "1.25.12", "1.24.9", "1.23.4"}

	for _, tc := range []struct {
		name    string
		channel Channel
		want    string
	}{{
		// All zero is the current release exactly.
		name:    "the current release",
		channel: Channel{},
		want:    "1.26.5",
	}, {
		// Two minors back, and the patch comes from that minor rather than today's.
		name:    "two minors back",
		channel: Channel{Minor: -2},
		want:    "1.24.9",
	}, {
		name:    "one minor back",
		channel: Channel{Minor: -1},
		want:    "1.25.12",
	}, {
		// One patch back within the current minor.
		name:    "one patch back",
		channel: Channel{Patch: -1},
		want:    "1.26.4",
	}, {
		// Both. One minor back lands on 1.25.12; one patch back from there is
		// whatever is published below it, which here is 1.24.9 -- a 1.25.11 that
		// go.dev never listed is not a version to name.
		name:    "a minor and a patch back",
		channel: Channel{Minor: -1, Patch: -1},
		want:    "1.24.9",
	}, {
		// Further back than anything published yields the oldest known, the most
		// permissive reading rather than a version Go never shipped.
		name:    "further back than exists",
		channel: Channel{Minor: -9},
		want:    "1.23.4",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.channel.Ceiling(published)
			if err != nil {
				t.Fatalf("Ceiling: %v", err)
			}
			if got != tc.want {
				t.Errorf("Ceiling() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChannelRejectsForwardOffsets checks that a positive offset is refused.
//
// A channel says how far behind the current release a project stays. An offset ahead of it
// names a version nobody can run, so it is a mistake rather than a preference.
func TestChannelRejectsForwardOffsets(t *testing.T) {
	published := []string{"1.26.5", "1.25.12"}
	for _, c := range []Channel{{Major: 1}, {Minor: 1}, {Patch: 1}} {
		if got, err := c.Ceiling(published); err == nil {
			t.Errorf("Ceiling(%+v) = %q, want an error for an offset ahead of the release", c, got)
		}
	}
	// And nothing published cannot yield a ceiling.
	if _, err := (Channel{}).Ceiling(nil); err == nil {
		t.Error("Ceiling(nil) succeeded, want an error with no releases known")
	}
	// An offset nothing published can satisfy is refused rather than ignored. Go has
	// only ever had major version 1, so asking to support a major back is asking for
	// something that does not exist -- and quietly treating it as the current release
	// would be the opposite of what was asked.
	if got, err := (Channel{Major: -1}).Ceiling(published); err == nil {
		t.Errorf("Ceiling(major -1) = %q, want an error: nothing below major 1 is published", got)
	}
}

// TestChannelAllows judges a declared version against the ceiling.
func TestChannelAllows(t *testing.T) {
	for _, tc := range []struct {
		declared, ceiling string
		want              bool
	}{
		{declared: "1.24", ceiling: "1.24.9", want: true},
		{declared: "1.24.9", ceiling: "1.24.9", want: true},
		{declared: "1.23", ceiling: "1.24.9", want: true},
		// Past the ceiling in the minor, which drops the consumers it promised.
		{declared: "1.25", ceiling: "1.24.9", want: false},
		{declared: "1.26.5", ceiling: "1.24.9", want: false},
		// Past it in the patch alone.
		{declared: "1.24.10", ceiling: "1.24.9", want: false},
		// Nothing declared, and nothing readable, are not breaches.
		{declared: "", ceiling: "1.24.9", want: true},
		{declared: "tip", ceiling: "1.24.9", want: true},
	} {
		t.Run(tc.declared+" vs "+tc.ceiling, func(t *testing.T) {
			if got := ChannelAllows(tc.declared, tc.ceiling); got != tc.want {
				t.Errorf("ChannelAllows(%q, %q) = %v, want %v",
					tc.declared, tc.ceiling, got, tc.want)
			}
		})
	}
}

// TestLoadGoChannel checks that a policy can state the release channel it keeps, one offset
// at a time.
func TestLoadGoChannel(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "go":      {"supported-minor": -2, "supported-patch": -1, "requires": "1.24"},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := p.GoChannel()
	if !ok {
		t.Fatal("GoChannel() reports unset, want the offsets")
	}
	if want := (Channel{Minor: -2, Patch: -1}); got != want {
		t.Errorf("GoChannel() = %+v, want %+v", got, want)
	}
	// The floor is the other bound, and independent of the channel.
	if floor, ok := p.GoRequires(); !ok || floor != "1.24" {
		t.Errorf("GoRequires() = %q, %v, want 1.24, true", floor, ok)
	}
}

// TestLoadGoChannelRejectsForwardOffsets checks that an offset ahead of the current release
// is refused when the file is read, since it names a version nobody can run.
func TestLoadGoChannelRejectsForwardOffsets(t *testing.T) {
	for _, field := range []string{"supported-major", "supported-minor", "supported-patch"} {
		path := write(t, t.TempDir(), "policy.json", `{
          "go":      {"`+field+`": 1},
          "actions": {"fail": {"exit": 1}},
          "modules": {"**": {"allow": "*"}},
          "rules":   [{"when": "go-unsupported", "then": "fail"}]
        }`)
		_, err := Load([]string{path})
		if err == nil {
			t.Errorf("Load(%s = 1) succeeded, want an error", field)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q does not name %q", err, field)
		}
	}
}

// TestLoadNoGoChannel checks that a policy silent about Go asks nothing.
//
// Zero everywhere is indistinguishable from unset by value, which is why Set exists: a
// policy that named no offsets must not be read as pinning the project to today's release.
func TestLoadNoGoChannel(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, ok := p.GoChannel(); ok {
		t.Errorf("GoChannel() = %+v, %v, want unset", got, ok)
	}
	if got, ok := p.GoRequires(); ok {
		t.Errorf("GoRequires() = %q, %v, want unset", got, ok)
	}
}

// TestParseReleasesKeepsPatchesAndPrereleases checks that the whole published history
// survives, since a band counts patches and may be asked to include release candidates.
//
// The default go.dev endpoint reports only the two current releases, which is why a patch
// offset had nothing to count and failed with "nothing below 1.26.5 is published". Asking
// for everything is the fix, and then a prerelease has to stay distinguishable: normalising
// to major.minor.patch would collapse 1.27rc1 and 1.27rc2 into one entry and collide with a
// real 1.27.0.
func TestParseReleasesKeepsPatchesAndPrereleases(t *testing.T) {
	body := `[
      {"version": "go1.27rc2",  "stable": false},
      {"version": "go1.27rc1",  "stable": false},
      {"version": "go1.26.5",   "stable": true},
      {"version": "go1.26.4",   "stable": true},
      {"version": "go1.26",     "stable": true},
      {"version": "go1.25.12",  "stable": true}
    ]`

	got, err := ParseReleases(true, []byte(body))
	if err != nil {
		t.Fatalf("ParseReleases: %v", err)
	}
	// Newest first, prereleases kept and distinct from each other.
	want := []Release{
		{Version: "1.27.0-rc2", Prerelease: true},
		{Version: "1.27.0-rc1", Prerelease: true},
		{Version: "1.26.5"},
		{Version: "1.26.4"},
		{Version: "1.26.0"},
		{Version: "1.25.12"},
	}
	if len(got) != len(want) {
		t.Fatalf("ParseReleases() = %v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i].Version != want[i].Version || got[i].Prerelease != want[i].Prerelease {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Without prereleases, the same body yields only the stable ones.
	got, err = ParseReleases(false, []byte(body))
	if err != nil {
		t.Fatalf("ParseReleases: %v", err)
	}
	for _, r := range got {
		if r.Prerelease {
			t.Errorf("got %+v, want stable releases only", r)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d stable releases, want 4", len(got))
	}
}
