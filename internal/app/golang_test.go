package app

import (
	"context"
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

// errUnreachable stands in for a network failure.
var errUnreachable = &unreachable{}

type unreachable struct{}

func (*unreachable) Error() string { return "go.dev is unreachable" }

var _ = time.Second

// TestCheckGoVersionJudgesBothEdges checks that a version outside the band is reported at
// either edge, and that the message names the resolved versions rather than the bounds.
//
// Too new drops consumers the project promised to support; too old is outside the set. One
// condition covers both, since what has to change is the same directive.
func TestCheckGoVersionJudgesBothEdges(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) {
		return []byte(`[
          {"version":"go1.26.5","stable":true},
          {"version":"go1.26.0","stable":true},
          {"version":"go1.25.12","stable":true},
          {"version":"go1.25.0","stable":true},
          {"version":"go1.24.0","stable":true}
        ]`), nil
	})()

	// The two most recent minors, so 1.25.0 through 1.26.5.
	rules := gate(t, `{
      "go":      {"supported-minor": ">=2"},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-outside-band", "then": "fail"}]
    }`)
	app := &AppEnv{}

	for _, tc := range []struct {
		declared string
		want     bool
	}{
		{declared: "1.25.0", want: false},
		{declared: "1.25.12", want: false},
		{declared: "1.26.5", want: false},
		// Below the floor: an unsupported line.
		{declared: "1.24.0", want: true},
		// Above the ceiling: newer than anything published, so it demands a toolchain
		// the project's consumers may not have.
		{declared: "1.27.0", want: true},
	} {
		t.Run(tc.declared, func(t *testing.T) {
			got := app.checkGoVersion(context.Background(), rules, tc.declared)
			if (len(got) > 0) != tc.want {
				t.Fatalf("checkGoVersion(%s) = %v, want a violation: %v", tc.declared, got, tc.want)
			}
			if len(got) == 0 {
				return
			}
			// The resolved edges, since ">=2" leaves a reader to work them out.
			for _, want := range []string{"1.25.0", "1.26.5"} {
				if !strings.Contains(got[0].Detail, want) {
					t.Errorf("detail %q does not name the edge %q", got[0].Detail, want)
				}
			}
			if got[0].Condition != policy.CondGoOutsideBand {
				t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondGoOutsideBand)
			}
		})
	}
}

// TestCheckGoVersionSilentWithoutABand checks that a policy saying nothing about Go asks
// nothing, and costs no request.
func TestCheckGoVersionSilentWithoutABand(t *testing.T) {
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
	app := &AppEnv{}
	if got := app.checkGoVersion(context.Background(), rules, "1.19"); len(got) != 0 {
		t.Errorf("checkGoVersion() = %v, want nothing without a band", got)
	}
	if asked != 0 {
		t.Errorf("asked go.dev %d times, want none: no policy asked about Go", asked)
	}
	if got := app.checkGoVersion(context.Background(), nil, "1.19"); len(got) != 0 {
		t.Errorf("checkGoVersion(nil) = %v, want nothing", got)
	}
}

// TestCheckGoVersionSilentWhenTheListFails checks that an unreachable go.dev does not invent a
// verdict.
//
// The band is unresolved, so whether a version sits inside it is not a question that can be
// answered. Reporting a breach there would be a guess.
func TestCheckGoVersionSilentWhenTheListFails(t *testing.T) {
	defer setGoReleasesFetch(func() ([]byte, error) { return nil, errUnreachable })()

	rules := gate(t, `{
      "go":      {"supported-minor": ">=2"},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-outside-band", "then": "fail"}]
    }`)
	app := &AppEnv{}
	if got := app.checkGoVersion(context.Background(), rules, "1.19"); len(got) != 0 {
		t.Errorf("checkGoVersion() = %v, want nothing when the band is unresolved", got)
	}
}
