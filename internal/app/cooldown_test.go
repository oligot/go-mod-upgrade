package app

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// TestPeriodsResolve checks where the two periods come from when a flag, an
// environment variable and a policy all have something to say.
//
// The caller on the command line is the most specific voice and wins. A policy is
// the next, since someone wrote it down deliberately. The built-in default is only
// the answer when nobody said anything -- and because the flag carries that default,
// "did the caller say" has to be asked of the command rather than inferred from the
// value, which is why CooldownSet exists.
func TestPeriodsResolve(t *testing.T) {
	day := 24 * time.Hour

	for _, tc := range []struct {
		name        string
		flag        string
		set         bool
		policy      string
		wantCooling time.Duration
	}{{
		// Nobody said, so the built-in default stands.
		name:        "neither",
		flag:        DefaultCooldown,
		wantCooling: 7 * day,
	}, {
		// Only the policy said.
		name:        "policy only",
		flag:        DefaultCooldown,
		policy:      "14d",
		wantCooling: 14 * day,
	}, {
		// The caller said, so the policy yields.
		name:        "caller overrides the policy",
		flag:        "21d",
		set:         true,
		policy:      "14d",
		wantCooling: 21 * day,
	}, {
		// Explicitly asking for the same value as the default is still asking, and
		// must beat a policy saying otherwise.
		name:        "caller names the default",
		flag:        DefaultCooldown,
		set:         true,
		policy:      "90d",
		wantCooling: 7 * day,
	}, {
		// Zero is a value, not an absence: it disables the cooldown.
		name:        "caller disables it",
		flag:        "0",
		set:         true,
		policy:      "14d",
		wantCooling: 0,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppEnv{
				Cooldown:    tc.flag,
				CooldownSet: tc.set,
				Churn:       DefaultChurn,
			}
			var policy *time.Duration
			if tc.policy != "" {
				d := mustPeriod(t, tc.policy)
				policy = &d
			}
			got, _, err := app.periods(policy, nil)
			if err != nil {
				t.Fatalf("periods: %v", err)
			}
			if got != tc.wantCooling {
				t.Errorf("cooldown = %v, want %v", got, tc.wantCooling)
			}
		})
	}
}

// TestPeriodsRejectChurnBelowCooldown checks that a churn window shorter than the
// cooldown is refused rather than silently doing nothing.
//
// Churn is detected by finding an earlier release inside the window. A window
// narrower than the cooldown cannot contain one, since every release inside it is
// also inside the cooldown -- so the setting would never fire and a caller who
// asked for it would never learn why.
func TestPeriodsRejectChurnBelowCooldown(t *testing.T) {
	app := &AppEnv{Cooldown: "30d", CooldownSet: true, Churn: "7d", ChurnSet: true}
	if _, _, err := app.periods(nil, nil); err == nil {
		t.Fatal("periods succeeded, want an error")
	} else {
		for _, want := range []string{"churn", "cooldown", "7d", "30d"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	}
}

// TestPeriodsAllowChurnEqualToCooldown checks the boundary: a window exactly as long
// as the cooldown is accepted, since a release at the far edge of it is settled and
// so is a genuine earlier release.
func TestPeriodsAllowChurnEqualToCooldown(t *testing.T) {
	app := &AppEnv{Cooldown: "7d", Churn: "7d"}
	if _, _, err := app.periods(nil, nil); err != nil {
		t.Errorf("periods: %v", err)
	}
}

// TestPeriodsRejectBadValue checks that an unreadable period fails, naming which of
// the two it was so the caller knows which to fix.
func TestPeriodsRejectBadValue(t *testing.T) {
	for _, tc := range []struct{ name, cooldown, churn, want string }{
		{name: "cooldown", cooldown: "7x", churn: DefaultChurn, want: "cooldown"},
		{name: "churn", cooldown: DefaultCooldown, churn: "soon", want: "churn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppEnv{Cooldown: tc.cooldown, Churn: tc.churn}
			_, _, err := app.periods(nil, nil)
			if err == nil {
				t.Fatal("periods succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// mustPeriod reads a period a test states as a literal, failing the test rather than
// returning an error the caller has to check.
func mustPeriod(t *testing.T, text string) time.Duration {
	t.Helper()
	d, err := module.ParseDuration(text)
	if err != nil {
		t.Fatalf("ParseDuration(%q): %v", text, err)
	}
	return d
}

// TestStep decides which version to offer from a release history.
//
// This is the whole judgement of the churn feature, so it is stated as a table over
// histories rather than mixed into the machinery that fetches them. The times are
// relative to a fixed "now", newest first, as the toolchain reports them.
func TestStep(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	cooldown, churn := 7*day, 28*day

	// ago builds a history from ages in days, newest first, naming versions by
	// position so a failure says which one was chosen.
	ago := func(days ...float64) []release {
		var h []release
		for i, d := range days {
			h = append(h, release{
				Version: "v1.0." + strconv.Itoa(len(days)-i-1),
				Time:    now.Add(-time.Duration(d * float64(day))),
			})
		}
		return h
	}

	for _, tc := range []struct {
		name         string
		history      []release
		wantOffer    string
		wantChurning bool
	}{{
		// The newest has settled, so there is nothing to decide: offer it.
		name:      "newest is settled",
		history:   ago(30, 60, 90),
		wantOffer: "v1.0.2",
	}, {
		// Exactly at the boundary has waited long enough.
		name:      "newest is exactly a cooldown old",
		history:   ago(7, 40),
		wantOffer: "v1.0.1",
	}, {
		// The real aws-sdk-go-v2 pattern: releases at 1d, 3d, 4d, 11d. The 11d one
		// is the newest that has settled, so that is what is offered.
		name:         "churning, so step back to the newest settled",
		history:      ago(1, 3, 4, 11, 40),
		wantOffer:    "v1.0.1",
		wantChurning: true,
	}, {
		// One fresh release and nothing else recent is not a pattern. Waiting a few
		// days is the honest answer, so nothing is offered rather than an older
		// version being dug up.
		name:      "one fresh release is not churn",
		history:   ago(1, 200, 400),
		wantOffer: "",
	}, {
		// The earlier release sits just inside the window, so it counts.
		name:         "earlier release at the edge of the window",
		history:      ago(1, 28),
		wantOffer:    "v1.0.0",
		wantChurning: true,
	}, {
		// Just outside, so it does not: this module released twice, months apart.
		name:      "earlier release just outside the window",
		history:   ago(1, 28.5),
		wantOffer: "",
	}, {
		// Churning, but every version in the history is too fresh. Nothing can be
		// offered; the caller reports that rather than pretending.
		name:         "churning with nothing settled to step back to",
		history:      ago(1, 2, 3, 4, 5, 6),
		wantOffer:    "",
		wantChurning: true,
	}, {
		// A history the toolchain gave nothing for decides nothing.
		name:      "no history",
		history:   nil,
		wantOffer: "",
	}, {
		// A single settled release is offered, with no earlier one needed.
		name:      "one settled release",
		history:   ago(90),
		wantOffer: "v1.0.0",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			offer, churning := step(tc.history, cooldown, churn, now)
			if offer != tc.wantOffer {
				t.Errorf("offer = %q, want %q", offer, tc.wantOffer)
			}
			if churning != tc.wantChurning {
				t.Errorf("churning = %v, want %v", churning, tc.wantChurning)
			}
		})
	}
}

// TestStepWithoutChurn checks that a zero churn window turns stepping off while
// leaving the cooldown itself in force.
//
// Someone who wants the cooldown honoured strictly -- wait, never step back -- has
// to be able to say so, and --churn=0 is how.
func TestStepWithoutChurn(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	history := []release{
		{Version: "v1.0.3", Time: now.Add(-1 * day)},
		{Version: "v1.0.2", Time: now.Add(-11 * day)},
	}

	// Nothing is offered: the newest is still cooling and stepping is off.
	offer, churning := step(history, 7*day, 0, now)
	if offer != "" || churning {
		t.Errorf("step() = %q, %v, want no offer and no churn", offer, churning)
	}
	// The settled version is still offered when it is the newest, so the cooldown
	// has not been disabled along with the stepping.
	offer, _ = step(history[1:], 7*day, 0, now)
	if offer != "v1.0.2" {
		t.Errorf("step() = %q, want v1.0.2", offer)
	}
}

// TestParseVersions checks which of a module's published versions are candidates to
// step back to.
//
// "go list -m -versions" reports everything ever published on one line, oldest first,
// including forms nothing should ever be stepped back to.
func TestParseVersions(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want []string
	}{{
		// The ordinary case, reversed to newest-first since that is the order the
		// walk needs.
		name: "reversed to newest first",
		out:  "example.com/m v1.0.0 v1.1.0 v1.2.0\n",
		want: []string{"v1.2.0", "v1.1.0", "v1.0.0"},
	}, {
		// A prerelease is not something to step back to: nobody waiting out a
		// cooldown wants an untested release candidate offered instead.
		name: "prereleases are not candidates",
		out:  "example.com/m v1.0.0 v1.1.0-rc1 v1.1.0 v2.0.0-preview.4+incompatible\n",
		want: []string{"v1.1.0", "v1.0.0"},
	}, {
		// A module with no tagged versions at all reports just its path.
		name: "no versions",
		out:  "example.com/m\n",
		want: nil,
	}, {
		// Nothing at all, which the toolchain gives for a path it cannot resolve.
		name: "no output",
		out:  "",
		want: nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseVersions([]byte(tc.out)); !slices.Equal(got, tc.want) {
				t.Errorf("parseVersions() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseVersionsCaps checks that only the newest few versions are considered, and
// that the limit is reported rather than applied silently.
//
// A module that has not had a settled release in twenty versions is churning far
// harder than this feature is meant to accommodate, and saying so beats issuing
// hundreds of queries. aws-sdk-go-v2 has 183 published versions.
func TestParseVersionsCaps(t *testing.T) {
	var published []string
	for i := range 40 {
		published = append(published, "v1.0."+strconv.Itoa(i))
	}
	out := "example.com/m " + strings.Join(published, " ") + "\n"

	got := parseVersions([]byte(out))
	if len(got) != stepLimit {
		t.Fatalf("parseVersions() returned %d versions, want %d", len(got), stepLimit)
	}
	// The newest are the ones kept, since those are the ones a walk reaches first.
	if got[0] != "v1.0.39" {
		t.Errorf("newest = %q, want v1.0.39", got[0])
	}
}

// TestParseReleaseTimes checks that the batched time lookup is read back per version.
func TestParseReleaseTimes(t *testing.T) {
	// The objects are concatenated rather than wrapped in an array, as go list
	// emits them.
	out := `{"Path":"example.com/m","Version":"v1.1.0","Time":"2026-07-31T20:13:11Z"}
	{"Path":"example.com/m","Version":"v1.0.0","Time":"2026-06-08T18:35:52Z"}`

	got, err := parseReleaseTimes([]byte(out))
	if err != nil {
		t.Fatalf("parseReleaseTimes: %v", err)
	}
	want := map[string]time.Time{
		"v1.1.0": time.Date(2026, 7, 31, 20, 13, 11, 0, time.UTC),
		"v1.0.0": time.Date(2026, 6, 8, 18, 35, 52, 0, time.UTC),
	}
	if len(got) != len(want) {
		t.Fatalf("got %d times, want %d", len(got), len(want))
	}
	for v, at := range want {
		if !got[v].Equal(at) {
			t.Errorf("time for %s = %v, want %v", v, got[v], at)
		}
	}
}

// TestParseReleaseTimesSkipsUndated checks that a version the toolchain gave no time
// for is left out rather than recorded as the zero time.
//
// A zero time reads as an ancient release, which would make an unknown version look
// like the settled one to step back to.
func TestParseReleaseTimesSkipsUndated(t *testing.T) {
	out := `{"Path":"example.com/m","Version":"v1.1.0"}
	{"Path":"example.com/m","Version":"v1.0.0","Error":{"Err":"unknown revision"}}`

	got, err := parseReleaseTimes([]byte(out))
	if err != nil {
		t.Fatalf("parseReleaseTimes: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing for versions with no usable date", got)
	}
}
