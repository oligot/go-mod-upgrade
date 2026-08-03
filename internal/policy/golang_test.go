package policy

import (
	"slices"
	"strings"
	"testing"
)

// TestParseReleases reads the supported Go versions from what go.dev publishes.
//
// Go supports the current release and the one before it, which is what the default
// endpoint reports: two minor versions, newest first. The patch level is dropped because
// a policy about "the last two releases" is about 1.26 and 1.25, not about which patch
// someone happens to be on.
func TestParseReleases(t *testing.T) {
	// The shape go.dev returns, trimmed to the fields that matter.
	body := `[
      {"version": "go1.26.5",  "stable": true},
      {"version": "go1.25.12", "stable": true}
    ]`

	got, err := ParseReleases([]byte(body))
	if err != nil {
		t.Fatalf("parseReleases: %v", err)
	}
	if want := []string{"1.26", "1.25"}; !slices.Equal(got, want) {
		t.Errorf("parseReleases() = %v, want %v", got, want)
	}
}

// TestParseReleasesSkipsPrereleases checks that a release candidate is not counted as a
// supported release.
//
// Asking go.dev for everything includes "go1.27rc1", which nothing should be required to
// support: it is not released, and a policy floor derived from it would reject every
// project.
func TestParseReleasesSkipsPrereleases(t *testing.T) {
	body := `[
      {"version": "go1.27rc1", "stable": false},
      {"version": "go1.26.5",  "stable": true},
      {"version": "go1.25.12", "stable": true},
      {"version": "go1.24.9",  "stable": false}
    ]`

	got, err := ParseReleases([]byte(body))
	if err != nil {
		t.Fatalf("parseReleases: %v", err)
	}
	if want := []string{"1.26", "1.25"}; !slices.Equal(got, want) {
		t.Errorf("parseReleases() = %v, want %v", got, want)
	}
}

// TestParseReleasesDeduplicatesPatches checks that several patches of one minor version
// count once.
//
// Asking for every release lists go1.26.5, go1.26.4 and go1.26.3, which are one
// supported release between them. Counting them separately would make "the last two"
// mean two patches of the same version.
func TestParseReleasesDeduplicatesPatches(t *testing.T) {
	body := `[
      {"version": "go1.26.5",  "stable": true},
      {"version": "go1.26.4",  "stable": true},
      {"version": "go1.26.3",  "stable": true},
      {"version": "go1.25.12", "stable": true},
      {"version": "go1.25.11", "stable": true}
    ]`

	got, err := ParseReleases([]byte(body))
	if err != nil {
		t.Fatalf("parseReleases: %v", err)
	}
	if want := []string{"1.26", "1.25"}; !slices.Equal(got, want) {
		t.Errorf("parseReleases() = %v, want %v", got, want)
	}
}

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
			if got, err := ParseReleases([]byte(tc.body)); err == nil {
				t.Errorf("parseReleases() = %v, want an error", got)
			}
		})
	}
}

// TestGoFloor works out the oldest Go version a policy permits.
//
// "the last two releases" is a count rather than a version, so the floor moves when Go
// releases. A policy naming a count says what it means once and stays correct; one
// naming 1.25 has to be edited every six months and is wrong in between.
func TestGoFloor(t *testing.T) {
	supported := []string{"1.26", "1.25", "1.24"}

	for _, tc := range []struct {
		name  string
		last  int
		want  string
		fails bool
	}{
		{name: "the last two", last: 2, want: "1.25"},
		{name: "the current release only", last: 1, want: "1.26"},
		{name: "more than exist", last: 9, want: "1.24"},
		{name: "none is not a window", last: 0, fails: true},
		{name: "negative", last: -1, fails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GoFloor(supported, tc.last)
			if tc.fails {
				if err == nil {
					t.Errorf("goFloor() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("goFloor: %v", err)
			}
			if got != tc.want {
				t.Errorf("goFloor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGoSupported judges a declared Go version against the window.
//
// The comparison is on the minor version, since that is what a release is. A project
// declaring a patch or a toolchain suffix is asking about the same release.
func TestGoSupported(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared string
		floor    string
		want     bool
	}{
		{name: "current", declared: "1.26", floor: "1.25", want: true},
		{name: "at the floor", declared: "1.25", floor: "1.25", want: true},
		{name: "below the floor", declared: "1.24", floor: "1.25", want: false},
		{name: "well below", declared: "1.19", floor: "1.25", want: false},
		// A patch level is the same release as its minor version.
		{name: "a patch at the floor", declared: "1.25.12", floor: "1.25", want: true},
		{name: "a patch below", declared: "1.24.9", floor: "1.25", want: false},
		// Ahead of the window is not outside it: a project on a release candidate is
		// not the problem this policy is about.
		{name: "ahead of the window", declared: "1.27", floor: "1.25", want: true},
		// Nothing declared says nothing, and must not read as ancient.
		{name: "nothing declared", declared: "", floor: "1.25", want: true},
		{name: "unreadable", declared: "tip", floor: "1.25", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := GoSupported(tc.declared, tc.floor); got != tc.want {
				t.Errorf("goSupported(%q, %q) = %v, want %v",
					tc.declared, tc.floor, got, tc.want)
			}
		})
	}
}

// TestLoadGoPolicy checks that a policy can say how many Go releases it supports.
func TestLoadGoPolicy(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "go":      {"releases": 2},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := p.GoReleases()
	if !ok || got != 2 {
		t.Errorf("GoReleases() = %v, %v, want 2, true", got, ok)
	}
}

// TestLoadGoPolicyRejectsNonsense checks that a count that cannot be a window is refused
// when the file is read.
func TestLoadGoPolicyRejectsNonsense(t *testing.T) {
	for _, count := range []string{"0", "-1"} {
		path := write(t, t.TempDir(), "policy.json", `{
          "go":      {"releases": `+count+`},
          "actions": {"fail": {"exit": 1}},
          "modules": {"**": {"allow": "*"}},
          "rules":   [{"when": "go-unsupported", "then": "fail"}]
        }`)
		if _, err := Load([]string{path}); err == nil {
			t.Errorf("Load(releases = %s) succeeded, want an error", count)
		} else if !strings.Contains(err.Error(), "releases") {
			t.Errorf("error %q does not name the field", err)
		}
	}
}

// TestLoadNoGoPolicy checks that a policy silent about Go versions asks nothing.
func TestLoadNoGoPolicy(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, ok := p.GoReleases(); ok {
		t.Errorf("GoReleases() = %v, %v, want unset", got, ok)
	}
}
