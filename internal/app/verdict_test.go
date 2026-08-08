package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// TestResolved works out where each module lands if a set of upgrades is taken.
//
// Go selects the highest version anything asks for, so taking one upgrade can move
// another module that was never chosen: aws-sdk-go-v2 v1.43.3 requires smithy-go
// v1.27.6, and taking the first drags the second whether or not anyone selected it.
// That is the whole reason a policy has to be checked against the outcome rather than
// against the modules on offer.
func TestResolved(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   map[string]string
		taking  []candidate
		asks    map[string]requires
		want    map[string]string
		dragged map[string]string
	}{{
		// The case from the transcript: one module chosen, two moved.
		name: "an upgrade drags a requirement",
		build: map[string]string{
			"github.com/aws/aws-sdk-go-v2": "v1.43.0",
			"github.com/aws/smithy-go":     "v1.27.3",
		},
		taking: []candidate{{Path: "github.com/aws/aws-sdk-go-v2", Version: "v1.43.3"}},
		asks: map[string]requires{
			"github.com/aws/aws-sdk-go-v2": {"github.com/aws/smithy-go": "v1.27.6"},
		},
		want: map[string]string{
			"github.com/aws/aws-sdk-go-v2": "v1.43.3",
			"github.com/aws/smithy-go":     "v1.27.6",
		},
		dragged: map[string]string{"github.com/aws/smithy-go": "github.com/aws/aws-sdk-go-v2"},
	}, {
		// A requirement below what is already held changes nothing: Go takes the
		// highest, and the build list already has it.
		name:   "a lower requirement is ignored",
		build:  map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v2.0.0"},
		taking: []candidate{{Path: "example.com/a", Version: "v1.1.0"}},
		asks:   map[string]requires{"example.com/a": {"example.com/b": "v1.5.0"}},
		want:   map[string]string{"example.com/a": "v1.1.0", "example.com/b": "v2.0.0"},
	}, {
		// A module the build list does not have yet still arrives.
		name:    "a new requirement is added",
		build:   map[string]string{"example.com/a": "v1.0.0"},
		taking:  []candidate{{Path: "example.com/a", Version: "v1.1.0"}},
		asks:    map[string]requires{"example.com/a": {"example.com/new": "v0.3.0"}},
		want:    map[string]string{"example.com/a": "v1.1.0", "example.com/new": "v0.3.0"},
		dragged: map[string]string{"example.com/new": "example.com/a"},
	}, {
		// Two upgrades asking for the same module: the higher wins, and that is who
		// is named as having dragged it.
		name:  "the highest requirement wins",
		build: map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0", "example.com/c": "v1.0.0"},
		taking: []candidate{
			{Path: "example.com/a", Version: "v1.1.0"},
			{Path: "example.com/b", Version: "v1.1.0"},
		},
		asks: map[string]requires{
			"example.com/a": {"example.com/c": "v1.2.0"},
			"example.com/b": {"example.com/c": "v1.5.0"},
		},
		want: map[string]string{
			"example.com/a": "v1.1.0", "example.com/b": "v1.1.0", "example.com/c": "v1.5.0",
		},
		dragged: map[string]string{"example.com/c": "example.com/b"},
	}, {
		// Nothing taken, so nothing moves.
		name:   "no upgrades",
		build:  map[string]string{"example.com/a": "v1.0.0"},
		taking: nil,
		want:   map[string]string{"example.com/a": "v1.0.0"},
	}, {
		// A version that will not parse is left alone rather than guessed at.
		name:   "an unreadable requirement is skipped",
		build:  map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0"},
		taking: []candidate{{Path: "example.com/a", Version: "v1.1.0"}},
		asks:   map[string]requires{"example.com/a": {"example.com/b": "not-a-version"}},
		want:   map[string]string{"example.com/a": "v1.1.0", "example.com/b": "v1.0.0"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, by := resolved(tc.build, tc.taking, tc.asks)
			if len(got) != len(tc.want) {
				t.Fatalf("resolved() = %v, want %v", got, tc.want)
			}
			for path, want := range tc.want {
				if got[path] != want {
					t.Errorf("%s = %q, want %q", path, got[path], want)
				}
			}
			// Who dragged a module is what lets a refusal name the upgrade to
			// reconsider, rather than the module that merely suffered it.
			for path, want := range tc.dragged {
				if by[path] != want {
					t.Errorf("%s was dragged by %q, want %q", path, by[path], want)
				}
			}
		})
	}
}

// TestDeniedByOutcome refuses the upgrades whose outcome a policy would forbid.
//
// The version that broke the transcript arrived transitively, so checking the modules
// on offer could never have caught it. Checking where the build list lands does.
func TestDeniedByOutcome(t *testing.T) {
	rules := loadPolicy(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {
        "github.com/aws/smithy-go": {"allow": "<= 1.27.4"},
        "**": {"allow": "*"}
      },
      "rules": [{"when": "version-denied", "then": "fail"}]
    }`)

	build := map[string]string{
		"github.com/aws/aws-sdk-go-v2": "v1.43.0",
		"github.com/aws/smithy-go":     "v1.27.3",
	}
	taking := []candidate{{Path: "github.com/aws/aws-sdk-go-v2", Version: "v1.43.3"}}
	asks := map[string]requires{
		"github.com/aws/aws-sdk-go-v2": {"github.com/aws/smithy-go": "v1.27.6"},
	}

	refused := deniedByOutcome(rules, build, taking, asks)
	if len(refused) != 1 {
		t.Fatalf("deniedByOutcome() = %v, want one refusal", refused)
	}
	got := refused[0]
	// The upgrade to refuse is the one selected, not the module that suffered it:
	// declining smithy-go would be declining something nobody asked for.
	if got.Upgrade != "github.com/aws/aws-sdk-go-v2" {
		t.Errorf("refused upgrade %q, want the selected module", got.Upgrade)
	}
	// But the reason has to name what the policy actually objected to.
	if !strings.Contains(got.Reason, "smithy-go") || !strings.Contains(got.Reason, "1.27.6") {
		t.Errorf("reason %q does not name the denied module and version", got.Reason)
	}

	// A policy the outcome satisfies refuses nothing.
	asks["github.com/aws/aws-sdk-go-v2"] = requires{"github.com/aws/smithy-go": "v1.27.4"}
	if refused := deniedByOutcome(rules, build, taking, asks); len(refused) != 0 {
		t.Errorf("deniedByOutcome() = %v, want nothing refused", refused)
	}

	// And no policy refuses nothing.
	if refused := deniedByOutcome(nil, build, taking, asks); len(refused) != 0 {
		t.Errorf("deniedByOutcome(nil) = %v, want nothing refused", refused)
	}
}

// TestDeniedByOutcomeNamesTheSelectedUpgrade checks that a module whose own target is
// denied is refused by its own name.
//
// Both shapes have to work: an upgrade denied for what it drags, and one denied for
// what it is.
func TestDeniedByOutcomeNamesTheSelectedUpgrade(t *testing.T) {
	rules := loadPolicy(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/m": {"allow": "< 2.0.0"}, "**": {"allow": "*"}},
      "rules":   [{"when": "version-denied", "then": "fail"}]
    }`)

	refused := deniedByOutcome(rules,
		map[string]string{"example.com/m": "v1.9.0"},
		[]candidate{{Path: "example.com/m", Version: "v2.0.0"}},
		nil)
	if len(refused) != 1 || refused[0].Upgrade != "example.com/m" {
		t.Fatalf("deniedByOutcome() = %v, want example.com/m refused", refused)
	}
	if !strings.Contains(refused[0].Reason, "2.0.0") {
		t.Errorf("reason %q does not name the version", refused[0].Reason)
	}
}

// TestVulnerableAfter finds the advisories a version would still be exposed to.
//
// An advisory covers every version below the one that fixes it, so upgrading to a
// version below FixedIn lands on something still vulnerable. That is worth catching
// before the upgrade rather than reporting it on the next run: a stepped-back version, or
// a module whose newest release is not yet the fixed one, can quietly move a project onto
// a release the database already knows about.
func TestVulnerableAfter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		to    string
		vulns []vulnerability
		want  []string
	}{{
		// The fix is ahead of where the upgrade lands, so it does not resolve it.
		name:  "lands below the fix",
		to:    "v1.2.0",
		vulns: []vulnerability{{ID: "GO-2026-0001", FixedIn: "v1.3.0"}},
		want:  []string{"GO-2026-0001"},
	}, {
		name:  "lands exactly on the fix",
		to:    "v1.3.0",
		vulns: []vulnerability{{ID: "GO-2026-0001", FixedIn: "v1.3.0"}},
		want:  nil,
	}, {
		name:  "lands above the fix",
		to:    "v1.4.0",
		vulns: []vulnerability{{ID: "GO-2026-0001", FixedIn: "v1.3.0"}},
		want:  nil,
	}, {
		// An advisory with no fix is not resolved by any version, so it is not a
		// reason to refuse one upgrade over another: there is nowhere to go.
		name:  "no fix exists",
		to:    "v1.4.0",
		vulns: []vulnerability{{ID: "GO-2026-0002", FixedIn: ""}},
		want:  nil,
	}, {
		// Two advisories fixed in different releases: only the one still ahead
		// applies.
		name: "several advisories",
		to:   "v1.3.0",
		vulns: []vulnerability{
			{ID: "GO-2026-0001", FixedIn: "v1.2.0"},
			{ID: "GO-2026-0003", FixedIn: "v1.5.0"},
		},
		want: []string{"GO-2026-0003"},
	}, {
		name:  "nothing known",
		to:    "v1.0.0",
		vulns: nil,
		want:  nil,
	}, {
		// A fix version that will not parse says nothing about where it sits.
		name:  "an unreadable fix version",
		to:    "v1.0.0",
		vulns: []vulnerability{{ID: "GO-2026-0004", FixedIn: "unknown"}},
		want:  nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, v := range vulnerableAfter(tc.to, tc.vulns) {
				got = append(got, v.ID)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("vulnerableAfter(%q) = %v, want %v", tc.to, got, tc.want)
			}
		})
	}
}

// TestExposedByOutcome refuses the upgrades that would land on a version an advisory
// still covers, including one reached transitively.
//
// The same shape as the policy gate: what matters is where the build list ends up, not
// what was selected. An upgrade that drags a dependency onto a vulnerable release is the
// case a per-module check cannot see.
func TestExposedByOutcome(t *testing.T) {
	build := map[string]string{
		"example.com/app": "v1.0.0",
		"example.com/lib": "v1.0.0",
	}
	vulns := vulnerabilities{
		"example.com/lib": []vulnerability{{ID: "GO-2026-0001", FixedIn: "v1.5.0", Called: true}},
	}

	// Taking the app drags lib to v1.2.0, which is still below the fix.
	refused := exposedByOutcome(build,
		[]candidate{{Path: "example.com/app", Version: "v1.1.0"}},
		map[string]requires{"example.com/app": {"example.com/lib": "v1.2.0"}},
		vulns)
	if len(refused) != 1 {
		t.Fatalf("exposedByOutcome() = %v, want one refusal", refused)
	}
	if refused[0].Upgrade != "example.com/app" {
		t.Errorf("refused %q, want the selected module", refused[0].Upgrade)
	}
	// The reason states the fact: which module, which version, which advisory.
	for _, want := range []string{"example.com/lib", "GO-2026-0001"} {
		if !strings.Contains(refused[0].Reason, want) {
			t.Errorf("reason %q does not mention %q", refused[0].Reason, want)
		}
	}
	// The remedy names the version that resolves it, kept apart from the reason so a
	// reader is told what to do rather than only what is wrong.
	if !strings.Contains(refused[0].Remedy, "1.5.0") {
		t.Errorf("remedy %q does not name the fixed version", refused[0].Remedy)
	}
	// And the identifiers are available without parsing prose.
	if !slices.Equal(refused[0].Advisories, []string{"GO-2026-0001"}) {
		t.Errorf("Advisories = %v, want the identifiers", refused[0].Advisories)
	}

	// Dragging it past the fix instead resolves the advisory, so nothing is refused.
	if refused := exposedByOutcome(build,
		[]candidate{{Path: "example.com/app", Version: "v1.1.0"}},
		map[string]requires{"example.com/app": {"example.com/lib": "v1.5.0"}},
		vulns); len(refused) != 0 {
		t.Errorf("exposedByOutcome() = %v, want nothing refused", refused)
	}
}

// TestExposedByOutcomeIgnoresWhatDidNotMove checks that a module already sitting on a
// vulnerable version does not block an unrelated upgrade.
//
// It is a problem this run did not cause, and enforce reports it. Refusing every upgrade
// over it would leave a reader unable to make progress on anything -- including on the
// upgrade that would fix it.
func TestExposedByOutcomeIgnoresWhatDidNotMove(t *testing.T) {
	build := map[string]string{
		"example.com/app":       "v1.0.0",
		"example.com/untouched": "v1.0.0",
	}
	vulns := vulnerabilities{
		"example.com/untouched": []vulnerability{{ID: "GO-2026-0001", FixedIn: "v9.0.0"}},
	}
	refused := exposedByOutcome(build,
		[]candidate{{Path: "example.com/app", Version: "v1.1.0"}}, nil, vulns)
	if len(refused) != 0 {
		t.Errorf("exposedByOutcome() = %v, want nothing: the vulnerable module did not move", refused)
	}
}

// TestExposedByOutcomeAllowsProgressTowardAFix checks that an upgrade moving a module
// closer to the fix, without reaching it, is still refused -- but that reaching it is
// permitted.
//
// Landing on a version an advisory covers is landing on a vulnerable version, however
// much better than the last one it is. Saying so is the point of the guard.
func TestExposedByOutcomeAllowsProgressTowardAFix(t *testing.T) {
	vulns := vulnerabilities{
		"example.com/m": []vulnerability{{ID: "GO-2026-0001", FixedIn: "v2.0.0"}},
	}
	build := map[string]string{"example.com/m": "v1.0.0"}

	// Still short of the fix.
	if refused := exposedByOutcome(build,
		[]candidate{{Path: "example.com/m", Version: "v1.9.0"}}, nil, vulns); len(refused) != 1 {
		t.Errorf("exposedByOutcome() = %v, want the upgrade refused", refused)
	}
	// Reaches it.
	if refused := exposedByOutcome(build,
		[]candidate{{Path: "example.com/m", Version: "v2.0.0"}}, nil, vulns); len(refused) != 0 {
		t.Errorf("exposedByOutcome() = %v, want the fix permitted", refused)
	}
}

// TestWithheldKeepsWhatWasNotRefused checks that a refused upgrade is dropped, the others
// are kept, and each refusal becomes a violation naming what to do.
//
// One module the policy will not permit must not cost a reader the rest of their
// selection, so the two results are independent.
func TestWithheldKeepsWhatWasNotRefused(t *testing.T) {
	mods := []module.Module{
		{Name: "example.com/keep"},
		{Name: "example.com/drop"},
		{Name: "example.com/also-keep"},
	}
	action := policy.Action{Name: "fail", Exit: 1}
	kept, found := withheld(mods, []refusal{{
		Upgrade:    "example.com/drop",
		Reason:     "affected by CVE-2026-0001",
		Remedy:     "upgrade to v2.0.0 or later",
		Advisories: []string{"CVE-2026-0001"},
	}}, action)

	var names []string
	for _, m := range kept {
		names = append(names, m.Name)
	}
	if want := []string{"example.com/keep", "example.com/also-keep"}; !slices.Equal(names, want) {
		t.Errorf("kept %v, want %v", names, want)
	}

	if len(found) != 1 {
		t.Fatalf("got %d violations, want 1", len(found))
	}
	if found[0].Condition != policy.CondUpgradeWithheld {
		t.Errorf("condition = %q, want %q", found[0].Condition, policy.CondUpgradeWithheld)
	}
	if found[0].Remedy == "" {
		t.Error("Remedy is empty; a finding a reader cannot act on is just an obstacle")
	}
	// The severity comes from the policy rather than from here.
	if found[0].Action != action {
		t.Errorf("action = %v, want the policy's %v", found[0].Action, action)
	}
}

// TestWithheldNothingRefused checks that the ordinary case reports nothing.
func TestWithheldNothingRefused(t *testing.T) {
	mods := []module.Module{{Name: "example.com/m"}}
	kept, found := withheld(mods, nil, policy.Action{})
	if len(found) != 0 {
		t.Errorf("got %v, want no violations", found)
	}
	if len(kept) != 1 {
		t.Errorf("kept %d modules, want 1", len(kept))
	}
}

// TestDeniedByOutcomeIgnoresTheCooldown pins the rule that a disabled cooldown does not
// reach the policy gate.
//
// --non-interactive with --cooldown=0 --churn=0 is how a scheduled run takes the newest
// releases, and the whole point of the gate is that it still refuses what a policy denies.
// A run with nobody at the keyboard is the one where an unnoticed denial matters most, and
// the gate never sees either period -- which is what this states, since the two are
// otherwise only connected by nothing having wired them together.
func TestDeniedByOutcomeIgnoresTheCooldown(t *testing.T) {
	rules := loadPolicy(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"golang.org/x/text": {"allow": "<= 0.20.0"}, "**": {"allow": "*"}},
      "rules":   [{"when": "version-denied", "then": "fail"}]
    }`)

	build := map[string]string{"golang.org/x/text": "v0.3.0"}
	taking := []candidate{{Path: "golang.org/x/text", Version: "v0.40.0"}}

	// Both periods zeroed, as --cooldown=0 --churn=0 leaves them. The cooldown is
	// package-level state the gate could have read, so it is set to the value that would
	// excuse the upgrade if it did.
	defer module.SetCooldown(0)
	module.SetCooldown(0)

	refused := deniedByOutcome(rules, build, taking, nil)
	require.Len(t, refused, 1, "want the denial to stand with no cooldown in force")
	require.Equal(t, "golang.org/x/text", refused[0].Upgrade)
	require.Contains(t, refused[0].Reason, "0.40.0",
		"want the reason to name the version the run would have landed on")
}

// TestInstalledForOutcomeStandsAtTheHighestRequirement checks which version stands
// for a module in the build list the refusal check reasons over, when the rows
// disagree about what is installed.
//
// A workspace splits one module into a row per requirement, so the same path arrives
// several times with different From versions. The build list holds one version per
// path, and what a policy objects to is the version the build would actually select:
// Go resolves a shared requirement to the highest of them, so that is the one the
// check has to reason from. Taking whichever row arrived last would make the answer
// depend on --sort.
func TestInstalledForOutcomeStandsAtTheHighestRequirement(t *testing.T) {
	// The rows a split workspace produces, newest first, which is the order the
	// default sort leads with: the wider move comes first.
	rows := []module.Module{
		mustModule(t, "example.com/lib", "v1.9.0", "v1.1.0"),
		mustModule(t, "example.com/lib", "v1.0.0", "v1.1.0"),
	}
	build, taking := installedForOutcome(rows)

	if got, want := build["example.com/lib"], "v1.9.0"; got != want {
		t.Errorf("build list holds %q, want %q -- the version MVS would select", got, want)
	}
	// Asked about once, however many rows named it: what a target requires is a
	// property of the target, and each entry costs a go list subprocess.
	if len(taking) != 1 {
		t.Fatalf("asking about %d candidates, want 1: %v", len(taking), taking)
	}
	if got := taking[0]; got.Path != "example.com/lib" || got.Version != "v1.1.0" {
		t.Errorf("asking about %+v, want example.com/lib at v1.1.0", got)
	}
}

// TestInstalledForOutcomeIsIndependentOfRowOrder checks that the build list does not
// depend on the order the rows arrive in.
//
// The rows reach this point in --sort order, so anything reading only the first or
// last of them would answer differently for the same workspace under a different
// sort. A policy decision that moves with the sort flag is not a policy decision.
func TestInstalledForOutcomeIsIndependentOfRowOrder(t *testing.T) {
	oldestFirst := []module.Module{
		mustModule(t, "example.com/lib", "v1.0.0", "v1.1.0"),
		mustModule(t, "example.com/lib", "v1.9.0", "v1.1.0"),
	}
	newestFirst := []module.Module{
		mustModule(t, "example.com/lib", "v1.9.0", "v1.1.0"),
		mustModule(t, "example.com/lib", "v1.0.0", "v1.1.0"),
	}
	oldest, _ := installedForOutcome(oldestFirst)
	newest, _ := installedForOutcome(newestFirst)
	if oldest["example.com/lib"] != newest["example.com/lib"] {
		t.Errorf("build list is %q one way and %q the other, want one answer",
			oldest["example.com/lib"], newest["example.com/lib"])
	}
}
