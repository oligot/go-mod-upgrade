package app

import (
	"strings"
	"testing"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/policy"
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
		if len(got) == 0 {
			t.Fatal("goReleases() returned nothing, want the payload")
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
	if got := checkGoVersion(rules, "1.19", false); len(got) != 0 {
		t.Errorf("checkGoVersion() = %v, want nothing without a go policy", got)
	}
	if asked != 0 {
		t.Errorf("asked go.dev %d times, want none: no policy asked about Go", asked)
	}
	// And nil rules are silent too, which is the no-policy case.
	if got := checkGoVersion(nil, "1.19", false); len(got) != 0 {
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
      "go":      {"supported-minor": -1},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	if got := checkGoVersion(rules, "1.30", false); len(got) != 0 {
		t.Errorf("checkGoVersion() = %v, want nothing when the window is unknown", got)
	}
}

// errUnreachable stands in for a network failure.
var errUnreachable = &unreachable{}

type unreachable struct{}

func (*unreachable) Error() string { return "go.dev is unreachable" }

var _ = time.Second

// TestCheckGoVersionBothBounds checks the two directions a release channel can be broken,
// which are opposite and independent.
//
// Declaring a version newer than the lookback allows drops consumers the project promised
// to support -- "go 1.26" refuses to build for anyone on 1.25. Declaring one older than
// the floor fails what the project needs of itself. A policy may set either or both.
func TestCheckGoVersionBothBounds(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) {
		return []byte(`[{"version":"go1.26.5","stable":true},{"version":"go1.25.12","stable":true}]`), nil
	})()

	// One minor back means declaring 1.25 or older.
	lookback := gate(t, `{
      "go":      {"supported-minor": -1},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	for _, tc := range []struct {
		declared string
		want     bool
	}{
		{declared: "1.25", want: false},
		{declared: "1.24", want: false}, // conservative, not a breach
		{declared: "1.26", want: true},  // drops everyone on 1.25
		{declared: "1.30", want: true},
	} {
		got := checkGoVersion(lookback, tc.declared, false)
		if (len(got) > 0) != tc.want {
			t.Errorf("declared %s: got %v, want a violation: %v", tc.declared, got, tc.want)
		}
		if len(got) > 0 && !strings.Contains(got[0].Detail, "1.25") {
			t.Errorf("detail %q does not name the ceiling", got[0].Detail)
		}
	}

	// A floor is the opposite question, and 1.24 now fails while 1.26 passes.
	floor := gate(t, `{
      "go":      {"requires": "1.25"},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-too-old", "then": "fail"}]
    }`)
	if got := checkGoVersion(floor, "1.24", false); len(got) != 1 {
		t.Errorf("checkGoVersion(1.24) = %v, want one violation below the floor", got)
	} else if got[0].Condition != policy.CondGoTooOld {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondGoTooOld)
	}
	if got := checkGoVersion(floor, "1.26", false); len(got) != 0 {
		t.Errorf("checkGoVersion(1.26) = %v, want nothing above the floor", got)
	}

	// Both set, and both broken at once is impossible -- but each still applies.
	both := gate(t, `{
      "go":      {"supported-minor": -1, "requires": "1.24"},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"},
                  {"when": "go-too-old", "then": "fail"}]
    }`)
	if got := checkGoVersion(both, "1.25", false); len(got) != 0 {
		t.Errorf("checkGoVersion(1.25) = %v, want nothing inside both bounds", got)
	}
	if got := checkGoVersion(both, "1.23", false); len(got) != 1 {
		t.Errorf("checkGoVersion(1.23) = %v, want the floor violated", got)
	}
	if got := checkGoVersion(both, "1.26", false); len(got) != 1 {
		t.Errorf("checkGoVersion(1.26) = %v, want the lookback violated", got)
	}
}

// TestCheckGoVersionWaivesThePatchOffsetForAnAdvisory checks that an advisory in the
// toolchain lets a project past its own patch conservatism.
//
// A channel is a promise about staying behind, and an advisory outranks it: holding two
// patches back is a preference, while running a Go with a known hole is a problem. The
// minor offset is untouched, since moving a minor is what would drop consumers -- only the
// patch bound is in the way of a fix.
func TestCheckGoVersionWaivesThePatchOffsetForAnAdvisory(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) {
		return []byte(`[
          {"version":"go1.26.5","stable":true},
          {"version":"go1.26.4","stable":true},
          {"version":"go1.25.12","stable":true}
        ]`), nil
	})()

	// One patch back: the ceiling is 1.26.4, so 1.26.5 is normally a breach.
	rules := gate(t, `{
      "go":      {"supported-patch": -1},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)

	if got := checkGoVersion(rules, "1.26.5", false); len(got) != 1 {
		t.Fatalf("checkGoVersion(1.26.5) = %v, want a violation past the patch ceiling", got)
	}
	// With an advisory, the patch offset is waived and the newest patch is permitted.
	if got := checkGoVersion(rules, "1.26.5", true); len(got) != 0 {
		t.Errorf("checkGoVersion(1.26.5, patched) = %v, want the patch offset waived", got)
	}

	// The minor bound still holds, since moving a minor drops consumers whatever the
	// advisory says.
	minor := gate(t, `{
      "go":      {"supported-minor": -1, "supported-patch": -1},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-unsupported", "then": "fail"}]
    }`)
	got := checkGoVersion(minor, "1.26.5", true)
	if len(got) != 1 {
		t.Fatalf("checkGoVersion(1.26.5, patched) = %v, want the minor bound to hold", got)
	}
	// And the message says the waiver happened, so a reader is not left wondering why
	// the ceiling moved.
	if !strings.Contains(got[0].Detail, "waived") {
		t.Errorf("detail %q does not mention the waiver", got[0].Detail)
	}
}
