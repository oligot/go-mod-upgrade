package app

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
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

// TestWithin keeps the releases a prompt should offer: those inside the churn window,
// newest first.
//
// The window is what the caller already said they consider recent activity, so it is
// the right bound on what to offer. Anything older is not a candidate a reader is
// choosing between -- it is history.
func TestWithin(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

	// The real smithy-go history: v1.27.3 sits at 37d, outside a 28d window.
	full := []release{
		{Version: "v1.27.6", Time: now.Add(-1 * day)},
		{Version: "v1.27.5", Time: now.Add(-5 * day)},
		{Version: "v1.27.4", Time: now.Add(-16 * day)},
		{Version: "v1.27.3", Time: now.Add(-37 * day)},
	}

	for _, tc := range []struct {
		name  string
		given []release
		churn time.Duration
		want  []string
	}{{
		name:  "inside the window only",
		given: full,
		churn: 28 * day,
		want:  []string{"v1.27.6", "v1.27.5", "v1.27.4"},
	}, {
		// Exactly at the edge is inside it, matching how churn itself counts.
		name:  "the edge is inside",
		given: full,
		churn: 37 * day,
		want:  []string{"v1.27.6", "v1.27.5", "v1.27.4", "v1.27.3"},
	}, {
		name:  "a narrow window",
		given: full,
		churn: 3 * day,
		want:  []string{"v1.27.6"},
	}, {
		name:  "nothing given",
		given: nil,
		churn: 28 * day,
		want:  nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range within(tc.given, tc.churn, now) {
				got = append(got, r.Version)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("within() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNewestSettled picks the version a prompt starts on: the newest that has been out
// longer than the cooldown.
//
// That is the one the tool recommends, so it is where the cursor belongs -- a reader
// who agrees presses enter and is done.
func TestNewestSettled(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	candidates := []release{
		{Version: "v1.27.6", Time: now.Add(-1 * day)},
		{Version: "v1.27.5", Time: now.Add(-5 * day)},
		{Version: "v1.27.4", Time: now.Add(-16 * day)},
	}

	for _, tc := range []struct {
		name     string
		given    []release
		cooldown time.Duration
		want     int
	}{{
		// Two are still cooling, so the third is it.
		name:     "skips what is still cooling",
		given:    candidates,
		cooldown: 7 * day,
		want:     2,
	}, {
		// Nothing is cooling, so the newest wins outright.
		name:     "the newest when all have settled",
		given:    candidates,
		cooldown: 0,
		want:     0,
	}, {
		// Everything is too fresh. There is no settled version to start on, which
		// the caller has to be able to tell from "the first one".
		name:     "none settled",
		given:    candidates,
		cooldown: 90 * day,
		want:     -1,
	}, {
		name:     "nothing given",
		given:    nil,
		cooldown: 7 * day,
		want:     -1,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newestSettled(tc.given, tc.cooldown, now); got != tc.want {
				t.Errorf("newestSettled() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestVersionPromptStartsOnTheSettledRelease drives the prompt the way a reader would
// and checks that pressing enter immediately takes the recommended version.
//
// The whole point of the default is that agreeing costs one keystroke, so this pins the
// keystroke rather than the index: a cursor placed correctly but a selection placed
// elsewhere would still install the wrong version.
func TestVersionPromptStartsOnTheSettledRelease(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()

	candidates := []release{
		{Version: "v1.27.6", Time: now.Add(-1 * day)},
		{Version: "v1.27.5", Time: now.Add(-5 * day)},
		{Version: "v1.27.4", Time: now.Add(-16 * day)},
	}
	cooldown := 7 * day
	statuses := versionStatuses(module.Module{}, candidates, cooldown, now, nil)
	start := firstEligible(statuses)
	_, options := versionList(candidates, statuses, now)

	// Enter with nothing touched: the default stands.
	m := press(t, newSelect("Which version?", options, []int{start}, 10))
	if got := m.chosen(); len(got) != 1 || candidates[got[0]].Version != "v1.27.4" {
		t.Errorf("enter alone chose %v, want just v1.27.4", got)
	}

	// The cursor starts there too, so moving is relative to the recommendation
	// rather than to the top of the list.
	m = newSelect("Which version?", options, []int{start}, 10)
	m.cursor = start
	up := press(t, m, "up")
	if up.cursor != start-1 {
		t.Errorf("cursor moved to %d, want %d", up.cursor, start-1)
	}

	// A reader who wants the newest can reach it, and picking it displaces the
	// default rather than adding to it. One version is installed, so a prompt that
	// left two marked would be showing something it cannot honour.
	m = newSelect("Which version?", options, []int{start}, 10)
	m.single = true
	m.cursor = start
	picked := press(t, m, "up", "up", " ")
	chosen := picked.chosen()
	if len(chosen) != 1 || candidates[chosen[0]].Version != "v1.27.6" {
		t.Errorf("chose %v, want just v1.27.6", chosen)
	}
}

// TestVersionStatuses says why each version is or is not on offer.
//
// Three answers, and they are not the same kind of thing. The cooldown is a judgement
// about time that a reader may overrule, having been told the age. A policy is a rule
// someone wrote down, and a version it refuses is not a choice at all. Saying "in
// cooldown" for both would flatten that distinction.
func TestVersionStatuses(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	candidates := []release{
		{Version: "v1.27.6", Time: now.Add(-1 * day)},
		{Version: "v1.27.5", Time: now.Add(-5 * day)},
		{Version: "v1.27.4", Time: now.Add(-16 * day)},
	}
	mod := module.Module{Name: "example.com/m"}
	mod.From = semver.MustParse("v1.27.3")
	mod.To = semver.MustParse("v1.27.4")

	// No policy: the cooldown alone decides.
	got := versionStatuses(mod, candidates, 7*day, now, nil)
	want := []string{statusCooling, statusCooling, statusEligible}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// A policy refusing everything above 1.27.4 marks those rather than hiding them:
	// a reader who cannot have the newest should be told why, not left wondering
	// where it went.
	rules := loadPolicy(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/m": {"allow": "<= 1.27.4"}},
      "rules":   [{"when": "version-denied", "then": "fail"}]
    }`)
	got = versionStatuses(mod, candidates, 7*day, now, rules)
	want = []string{statusDenied, statusDenied, statusEligible}
	if !slices.Equal(got, want) {
		t.Errorf("with a policy: got %v, want %v", got, want)
	}

	// A policy that covers the module but denies nothing leaves the cooldown to
	// decide, so a permissive rule does not read as refusing everything.
	rules = loadPolicy(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	got = versionStatuses(mod, candidates, 7*day, now, rules)
	want = []string{statusCooling, statusCooling, statusEligible}
	if !slices.Equal(got, want) {
		t.Errorf("with a permissive policy: got %v, want %v", got, want)
	}
}

// TestFirstEligible finds where the cursor starts: the newest version nothing refuses.
//
// A version a policy denies cannot be the default, however settled it is -- starting
// there would offer as the recommendation something the run would then fail on.
func TestFirstEligible(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []string
		want     int
	}{{
		name:     "the first eligible one",
		statuses: []string{statusCooling, statusCooling, statusEligible},
		want:     2,
	}, {
		name:     "skips a denial to reach it",
		statuses: []string{statusDenied, statusEligible, statusEligible},
		want:     1,
	}, {
		// Nothing is on offer, which the caller has to tell from "the first one".
		name:     "none eligible",
		statuses: []string{statusDenied, statusCooling},
		want:     -1,
	}, {
		name:     "nothing given",
		statuses: nil,
		want:     -1,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstEligible(tc.statuses); got != tc.want {
				t.Errorf("firstEligible() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestVersionListHasAHeading checks that the columns are labelled and that the heading
// lines up with what it labels.
//
// Three unlabelled columns of numbers and words leave a reader guessing which is the
// age. The heading is built beside the rows so the padding cannot drift apart from
// them.
func TestVersionListHasAHeading(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()

	candidates := []release{
		{Version: "v1.27.10", Time: now.Add(-1 * day)},
		{Version: "v1.27.4", Time: now.Add(-16 * day)},
	}
	heading, options := versionList(candidates,
		[]string{statusCooling, statusEligible}, now)

	for _, want := range []string{"VERSION", "AGE", "STATUS"} {
		if !strings.Contains(heading, want) {
			t.Errorf("heading %q does not name %q", heading, want)
		}
	}
	// A left-aligned column starts where its heading does, so the wider version does
	// not push its neighbour out from under the label.
	if strings.Index(heading, "STATUS") != strings.Index(options[0], statusCooling) {
		t.Errorf("STATUS is not aligned with its heading:\n%q\n%q", heading, options[0])
	}
	// The age is right-aligned, so it is the ends that line up rather than the
	// starts: "1d" and "2w" finish under the last letter of AGE.
	ageEnds := strings.Index(heading, "AGE") + len("AGE")
	for i, want := range []string{"1d", "2w"} {
		if got := strings.Index(options[i], want) + len(want); got != ageEnds {
			t.Errorf("%s ends at %d, want %d:\n%q\n%q", want, got, ageEnds, heading, options[i])
		}
	}
}

// loadPolicy writes a policy file and loads it, for a test that needs one.
func loadPolicy(t *testing.T, body string) *policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	p, err := policy.Load([]string{path})
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	return p
}
