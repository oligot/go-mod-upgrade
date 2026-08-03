package app

import (
	"strings"
	"testing"
	"time"
)

// TestGoReleasesCacheIsReused checks that the release list is fetched once and reused, so
// a run does not ask go.dev per directory.
//
// Go releases twice a year, so a list from this morning is as good as one from this
// second. A workspace with twenty members would otherwise make twenty identical
// requests.
func TestGoReleasesCacheIsReused(t *testing.T) {
	asked := 0
	defer setGoReleasesFetch(func() ([]byte, error) {
		asked++
		return []byte(`[{"version":"go1.26.5","stable":true},{"version":"go1.25.12","stable":true}]`), nil
	})()

	for range 3 {
		got, err := goReleases()
		if err != nil {
			t.Fatalf("goReleases: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("goReleases() = %v, want two releases", got)
		}
	}
	if asked != 1 {
		t.Errorf("asked go.dev %d times, want 1", asked)
	}
}

// TestGoReleasesReportsAFailure checks that an unreachable go.dev is an error rather than
// an empty window.
//
// An empty window permits everything, so a policy asking about Go versions would stop
// asking without saying so.
func TestGoReleasesReportsAFailure(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) {
		return nil, errUnreachable
	})()

	if got, err := goReleases(); err == nil {
		t.Errorf("goReleases() = %v, want an error", got)
	}
}

// TestCheckGoVersion reports a project declaring a Go version older than the policy
// supports.
func TestCheckGoVersion(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) {
		return []byte(`[{"version":"go1.26.5","stable":true},{"version":"go1.25.12","stable":true}]`), nil
	})()

	rules := gate(t, `{
      "go":      {"releases": 2},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)

	for _, tc := range []struct {
		name     string
		declared string
		want     bool
	}{
		{name: "current release", declared: "1.26.5", want: false},
		{name: "the older supported release", declared: "1.25", want: false},
		{name: "one release behind the window", declared: "1.24", want: true},
		{name: "years behind", declared: "1.19", want: true},
		// Nothing declared says nothing rather than reading as ancient.
		{name: "nothing declared", declared: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkGoVersion(rules, tc.declared)
			if (got != nil) != tc.want {
				t.Fatalf("checkGoVersion(%q) = %v, want a violation: %v",
					tc.declared, got, tc.want)
			}
			if got == nil {
				return
			}
			// The message has to name the window and what the project declared, so a
			// reader knows how far behind they are without looking it up.
			for _, want := range []string{tc.declared, "1.25"} {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q does not mention %q", got.Detail, want)
				}
			}
		})
	}
}

// TestCheckGoVersionSilentWithoutAPolicy checks that a policy saying nothing about Go
// versions asks nothing, and costs no request.
func TestCheckGoVersionSilentWithoutAPolicy(t *testing.T) {
	asked := 0
	defer setGoReleasesFetch(func() ([]byte, error) {
		asked++
		return []byte(`[{"version":"go1.26.5","stable":true}]`), nil
	})()

	rules := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	if got := checkGoVersion(rules, "1.19"); got != nil {
		t.Errorf("checkGoVersion() = %v, want nothing without a go policy", got)
	}
	if asked != 0 {
		t.Errorf("asked go.dev %d times, want none: no policy asked about Go", asked)
	}
	// And nil rules are silent too, which is the no-policy case.
	if got := checkGoVersion(nil, "1.19"); got != nil {
		t.Errorf("checkGoVersion(nil) = %v, want nothing", got)
	}
}

// TestCheckGoVersionSilentWhenTheListFails checks that an unreachable go.dev does not
// invent a verdict.
//
// The window is unknown, so nothing can be said about whether a version is inside it.
// Reporting a breach would be a guess, and reporting nothing is what a policy about Go
// versions does when it cannot tell.
func TestCheckGoVersionSilentWhenTheListFails(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) { return nil, errUnreachable })()

	rules := gate(t, `{
      "go":      {"releases": 2},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	if got := checkGoVersion(rules, "1.19"); got != nil {
		t.Errorf("checkGoVersion() = %v, want nothing when the window is unknown", got)
	}
}

// errUnreachable stands in for a network failure.
var errUnreachable = &unreachable{}

type unreachable struct{}

func (*unreachable) Error() string { return "go.dev is unreachable" }

var _ = time.Second
