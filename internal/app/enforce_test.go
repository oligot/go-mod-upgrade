package app

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// gate builds a policy from a JSON body, failing the test if it is unusable.
func gate(t *testing.T, body string) *policy.Policy {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/policy.json"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	p, err := policy.Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

// A policy that refuses what the code reaches, notes what it does not, and
// insists every module be named.
const gating = `{
  "actions": {
    "fail": {"exit": 1},
    "warn": {"exit": 0, "log": "warn"}
  },
  "modules": {
    "example.com/allowed": {"allow": "*"}
  },
  "rules": [
    {"when": "vuln-reachable", "then": "fail"},
    {"when": "vuln-present",   "then": "warn"},
    {"when": "not-allowed",    "then": "fail"}
  ]
}`

func TestEnforceConditions(t *testing.T) {
	p := gate(t, gating)

	reachable := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.1")
	reachable.Vulns = []string{"CVE-0000-0001"}
	reachable.Reachable = 1

	present := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.1")
	present.Vulns = []string{"CVE-0000-0002"}

	unlisted := mustModule(t, "example.com/unlisted", "v1.0.0", "v1.0.1")
	clean := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.1")

	cases := []struct {
		name string
		mod  module.Module
		// want is the condition expected, empty when nothing should be raised.
		want  string
		fails bool
	}{
		{"reached by this code", reachable, policy.CondVulnReachable, true},
		{"present but not reached", present, policy.CondVulnPresent, false},
		{"no rule covers it", unlisted, policy.CondNotAllowed, true},
		{"nothing to say", clean, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := enforce(p, []module.Module{c.mod})
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %d violations, want none", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d violations, want 1: %+v", len(got), got)
			}
			if got[0].Condition != c.want {
				t.Errorf("condition = %q, want %q", got[0].Condition, c.want)
			}
			if got[0].Action.Fails() != c.fails {
				t.Errorf("fails = %v, want %v", got[0].Action.Fails(), c.fails)
			}
		})
	}
}

// TestEnforceVersionDenied checks that a module a rule covers but whose installed
// version falls outside it is reported as a local policy exception.
//
// Not "version-denied": that condition is about refusing a version, and this one is
// already in the tree. Someone upgraded past the policy and is accountable, so the run
// reports it and moves on rather than failing over something it cannot undo.
func TestEnforceVersionDenied(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/pinned": {"allow": ">= v2.0.0"}},
      "rules":   [{"when": "local-policy-exception", "then": "fail"}]
    }`)

	got := enforce(p, []module.Module{mustModule(t, "example.com/pinned", "v1.0.0", "v1.0.1")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	if got[0].Condition != policy.CondLocalPolicyException {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondLocalPolicyException)
	}
	// The message has to say what would satisfy the rule.
	if !strings.Contains(got[0].Detail, ">= v2.0.0") {
		t.Errorf("detail %q does not name the constraint", got[0].Detail)
	}
}

// TestEnforceSilentWhenNoRule checks that a condition the policy says nothing
// about raises nothing, so a policy about versions does not report advisories it
// never asked to hear about.
func TestEnforceSilentWhenNoRule(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "not-allowed", "then": "fail"}]
    }`)

	vulnerable := mustModule(t, "example.com/x", "v1.0.0", "v1.0.1")
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	vulnerable.Reachable = 1

	if got := enforce(p, []module.Module{vulnerable}); len(got) != 0 {
		t.Errorf("got %+v, want nothing: the policy asked only about permission", got)
	}
}

// TestReportFails checks that report says whether anything failed the run, and that a
// warning alongside a failure still counts as failing.
//
// Whether it failed is the fact report can know. Which status to leave with depends on
// how the run was invoked, so that is decided by ExitStatus rather than here -- see
// TestExitStatusDerivesFromWhatFailed for the codes themselves.
func TestReportFails(t *testing.T) {
	fail := policy.Action{Name: "fail", Exit: 1}
	halt := policy.Action{Name: "halt", Exit: 42}
	warn := policy.Action{Name: "warn", Exit: 0}

	cases := []struct {
		name string
		in   []violation
		want bool
	}{
		{"nothing to report", nil, false},
		{"a warning alone", []violation{{Action: warn}}, false},
		{"a failure", []violation{{Action: fail}}, true},
		{"a warning does not mask a failure", []violation{{Action: warn}, {Action: fail}}, true},
		{"several failures", []violation{{Action: fail}, {Action: halt}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := report(c.in); got != c.want {
				t.Errorf("report() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEnforceOrdersFailuresFirst checks that the failures lead, since a long
// report is read from the top.
func TestEnforceOrdersFailuresFirst(t *testing.T) {
	p := gate(t, gating)

	present := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.1")
	present.Vulns = []string{"CVE-0000-0002"}
	unlisted := mustModule(t, "example.com/unlisted", "v1.0.0", "v1.0.1")

	// The warning is listed first, so a stable sort has to move it.
	got := enforce(p, []module.Module{present, unlisted})
	if len(got) != 2 {
		t.Fatalf("got %d violations, want 2", len(got))
	}
	if !got[0].Action.Fails() {
		t.Errorf("first reported is %q, want the failure", got[0].Condition)
	}
}

// TestEnforceSeesIgnoredModules pins the rule that --ignore withholds an
// upgrade without exempting the module from review.
//
// The two pull in opposite directions, so both are asserted: dropping the
// module at discovery would silently bypass a security gate, and keeping it in
// the upgrade list would upgrade something the caller declined.
func TestEnforceSeesIgnoredModules(t *testing.T) {
	p := gate(t, gating)

	ignored := mustModule(t, "example.com/unlisted", "v1.0.0", "v1.0.1")
	ignored.Ignored = true

	// The policy still objects to it.
	got := enforce(p, []module.Module{ignored})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want the policy to still check it", len(got))
	}
	if got[0].Condition != policy.CondNotAllowed {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondNotAllowed)
	}

	// It is not offered for upgrade.
	if left := upgradable([]module.Module{ignored}, false); len(left) != 0 {
		t.Errorf("got %d upgradable, want an ignored module withheld", len(left))
	}
}

// TestEnforceSeesModulesWithNoUpgrade pins the rule that being up to date does
// not exempt a module from the policy.
//
// Discovery used to drop a module when "go list -m -u" reported no newer
// version, which meant an allow-list silently ignored every module already at
// its newest version, and a deny could not fail the run. That is the worst case
// for an advisory rather than the safest: an abandoned module is both
// unupgradable and permanently vulnerable.
func TestEnforceSeesModulesWithNoUpgrade(t *testing.T) {
	p := gate(t, gating)

	// From and To are equal, as discovery now reports a current module.
	current := mustModule(t, "example.com/unlisted", "v1.0.0", "v1.0.0")

	got := enforce(p, []module.Module{current})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want the policy to check a current module", len(got))
	}
	if got[0].Condition != policy.CondNotAllowed {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondNotAllowed)
	}

	// A reachable advisory in a module with nothing to upgrade to must still
	// fail, since there is no upgrade that would resolve it.
	vulnerable := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.0")
	vulnerable.Vulns = []string{"CVE-0000-0003"}
	vulnerable.Reachable = 1

	got = enforce(p, []module.Module{vulnerable})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want a reachable advisory reported", len(got))
	}
	if got[0].Condition != policy.CondVulnReachable {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondVulnReachable)
	}
	if !got[0].Action.Fails() {
		t.Error("a reachable advisory must fail the run")
	}

	// Neither is offered for upgrade, since there is nothing to upgrade to.
	if left := upgradable([]module.Module{current, vulnerable}, false); len(left) != 0 {
		t.Errorf("got %d upgradable, want a current module withheld", len(left))
	}
}

// A policy responding to the ways a module can be disowned: by its author, and
// by a reviewer who noticed it was abandoned.
const disowned = `{
  "actions": {
    "fail": {"exit": 1},
    "warn": {"exit": 0, "log": "warn"}
  },
  "modules": {
    "example.com/allowed":  {"allow": "*"},
    "example.com/orphaned": {
      "allow": "*",
      "archived": "unmaintained since 2018; migrate to example.com/successor"
    }
  },
  "rules": [
    {"when": "deprecated", "then": "warn"},
    {"when": "retracted",  "then": "fail"},
    {"when": "archived",   "then": "warn"},
    {"when": "not-allowed", "then": "fail"}
  ]
}`

// TestEnforceAuthorSignals covers the two signals go list reports, which say
// nothing about whether a module is permitted: one can be allowed and still have
// been disowned upstream.
func TestEnforceAuthorSignals(t *testing.T) {
	p := gate(t, disowned)

	deprecated := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.0")
	deprecated.Deprecated = "Use example.com/successor instead."

	got := enforce(p, []module.Module{deprecated})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want the deprecation reported", len(got))
	}
	if got[0].Condition != policy.CondDeprecated {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondDeprecated)
	}
	// No upgrade resolves a deprecation, so the author's message is the advice.
	if !strings.Contains(got[0].Detail, "example.com/successor") {
		t.Errorf("detail = %q, want the author's message", got[0].Detail)
	}

	retracted := mustModule(t, "example.com/allowed", "v1.0.0", "v1.1.0")
	retracted.Retracted = []string{"Published prematurely"}

	got = enforce(p, []module.Module{retracted})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want the retraction reported", len(got))
	}
	if got[0].Condition != policy.CondRetracted {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondRetracted)
	}
	if !got[0].Action.Fails() {
		t.Error("this policy fails on a retraction")
	}
	// The reason has to reach the report, since it is why the version went.
	if !strings.Contains(got[0].Detail, "Published prematurely") {
		t.Errorf("detail = %q, want the author's reason", got[0].Detail)
	}
}

// TestEnforceArchivedAssertion covers the condition a human asserts, which
// exists because an abandoned module often declares nothing at all.
func TestEnforceArchivedAssertion(t *testing.T) {
	p := gate(t, disowned)

	// Permitted, current, and carrying no advisory: nothing observable is wrong
	// with it. Only the assertion says otherwise.
	orphaned := mustModule(t, "example.com/orphaned", "v1.0.0", "v1.0.0")

	got := enforce(p, []module.Module{orphaned})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want the assertion reported", len(got))
	}
	if got[0].Condition != policy.CondArchived {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondArchived)
	}
	// The reason is the whole value of an assertion the toolchain cannot check.
	if !strings.Contains(got[0].Detail, "unmaintained since 2018") {
		t.Errorf("detail = %q, want the reason the reviewer gave", got[0].Detail)
	}

	// A module nobody marked raises nothing, which is the limit of the feature:
	// it narrows the gap rather than closing it.
	unmarked := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.0")
	if got := enforce(p, []module.Module{unmarked}); len(got) != 0 {
		t.Errorf("got %d violations, want nothing for an unmarked module", len(got))
	}
}

// TestEnforceSilentWithoutRules checks that the new conditions cost nothing when
// a policy does not mention them, so an existing file behaves as it did.
func TestEnforceSilentWithoutRules(t *testing.T) {
	// The original policy, which says nothing about being disowned.
	p := gate(t, gating)

	mod := mustModule(t, "example.com/allowed", "v1.0.0", "v1.0.0")
	mod.Deprecated = "Use example.com/successor instead."
	mod.Retracted = []string{"Published prematurely"}

	if got := enforce(p, []module.Module{mod}); len(got) != 0 {
		t.Errorf("got %d violations, want silence where no rule asks", len(got))
	}
}

// TestEnforceStillJudgesTheInstalledVersion checks that a module already sitting on a
// forbidden version is reported even when no upgrade is on offer.
//
// The two are different problems: one says the tree is wrong now, the other that a run
// would make it wrong. Both are worth saying, and gaining the second must not lose the
// first.
func TestEnforceStillJudgesTheInstalledVersion(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/m": {"allow": ">= v2.0.0"}},
      "rules":   [{"when": "local-policy-exception", "then": "fail"}]
    }`)

	// Nothing newer, so From and To are the same: the tree itself is in breach.
	got := enforce(p, []module.Module{mustModule(t, "example.com/m", "v1.0.0", "v1.0.0")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1 for the installed version", len(got))
	}
	if !strings.Contains(got[0].Detail, ">= v2.0.0") {
		t.Errorf("detail %q does not name the constraint", got[0].Detail)
	}
}

// TestEnforceReportsOneVersionViolation checks that an upgrade forbidden at both ends is
// reported once rather than twice.
//
// Two lines for one module reads as two problems needing two fixes, when allowing the
// module once resolves both.
func TestEnforceReportsOneVersionViolation(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/m": {"allow": ">= v9.0.0"}},
      "rules":   [{"when": "local-policy-exception", "then": "fail"}]
    }`)

	got := enforce(p, []module.Module{mustModule(t, "example.com/m", "v1.0.0", "v2.0.0")})
	if len(got) != 1 {
		t.Errorf("got %d violations, want 1:\n%v", len(got), got)
	}
}

// TestEnforceOffersAreALocalPolicyException checks that a version already installed but
// forbidden is a warning rather than a failure, and says why.
//
// Someone upgraded past the policy and is accountable for it, so the run moves forward.
// And the tree is not necessarily the thing that is wrong: a shop with a more informed
// opinion, or a policy that used to be wider, can leave a local policy trailing what the
// project actually decided. Calling it a "local policy exception" says which of the two
// to go and look at, where "denied" only asserts the tree is at fault.
func TestEnforceOffersAreALocalPolicyException(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}, "note": {"exit": 0, "log": "warn"}},
      "modules": {"example.com/m": {"allow": "<= 1.2.0"}},
      "rules":   [{"when": "version-denied", "then": "fail"},
                  {"when": "local-policy-exception", "then": "note"}]
    }`)

	// Installed past what the policy allows, with nothing newer on offer.
	got := enforce(p, []module.Module{mustModule(t, "example.com/m", "v1.3.0", "v1.3.0")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1:\n%v", len(got), got)
	}
	if got[0].Condition != policy.CondLocalPolicyException {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondLocalPolicyException)
	}
	// A warning, so the run moves forward: the upgrade already happened and failing
	// now neither undoes it nor tells anyone something they can act on today.
	if got[0].Action.Fails() {
		t.Errorf("action %v fails the run, want a warning", got[0].Action)
	}
	// The message names the constraint that was outgrown, so a reader can judge
	// whether to widen the policy or roll the module back.
	if !strings.Contains(got[0].Detail, "<= 1.2.0") {
		t.Errorf("detail %q does not name the constraint", got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "1.3.0") {
		t.Errorf("detail %q does not name the installed version", got[0].Detail)
	}
}

// TestEnforceStillFailsWhenNothingWasInstalled checks that a module the policy refuses
// outright is still a failure, since no upgrade put it there to be accountable for.
//
// The exception is for a version someone chose. A module no rule covers, or one a rule
// denies by path, is a different problem and keeps its own severity.
func TestEnforceStillFailsWhenNothingWasInstalled(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/m": {"deny": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)

	got := enforce(p, []module.Module{mustModule(t, "example.com/m", "v1.0.0", "v1.0.0")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	if !got[0].Action.Fails() {
		t.Errorf("action %v does not fail, want a denial to fail", got[0].Action)
	}
}

// TestEnforceExceptionStatesThePolicyFirst checks the order the message reads in: what
// the policy permits, then what is installed and why it stands as an exception.
//
// A reader meeting this line does not yet know what the rule is, so the rule comes
// first. The exception then means something.
func TestEnforceExceptionStatesThePolicyFirst(t *testing.T) {
	p := gate(t, `{
      "actions": {"note": {"exit": 0, "log": "warn"}},
      "modules": {"example.com/m": {"allow": "<= 1.2.0"}},
      "rules":   [{"when": "local-policy-exception", "then": "note"}]
    }`)

	got := enforce(p, []module.Module{mustModule(t, "example.com/m", "v1.3.0", "v1.3.0")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1:\n%v", len(got), got)
	}
	detail := got[0].Detail
	// What the policy permits leads, and the installed version follows it.
	permits, installed := strings.Index(detail, "<= 1.2.0"), strings.Index(detail, "1.3.0")
	if permits < 0 || installed < 0 {
		t.Fatalf("detail %q does not name both the constraint and the version", detail)
	}
	if permits > installed {
		t.Errorf("detail %q states the installed version before the policy", detail)
	}
	// The rule that decided it, so a reader knows which line of which file to edit.
	if !strings.Contains(detail, "example.com/m") {
		t.Errorf("detail %q does not name the rule", detail)
	}
}

// TestEnforceExceptionNamesTheCooldownOnlyWhenItIsTheReason checks that the cooldown is
// mentioned when waiting would resolve the exception, and not when it would not.
//
// A constraint compares version numbers, so time does not move it: 1.27.6 never
// satisfies "<= 1.27.4" however long anyone waits. Saying "4d until it is permitted"
// there would be a promise the next run breaks. The cooldown clause therefore belongs
// only where the cooldown is what objects.
func TestEnforceExceptionNamesTheCooldownOnlyWhenItIsTheReason(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()
	module.SetCooldown(7 * day)
	defer module.SetCooldown(0)

	// The constraint permits anything, so the cooldown is the only objection and
	// waiting is the answer.
	cooling := gate(t, `{
      "actions": {"note": {"exit": 0, "log": "warn"}},
      "modules": {"example.com/m": {"allow": "*"}},
      "rules":   [{"when": "local-policy-exception", "then": "note"}]
    }`)
	fresh := mustModule(t, "example.com/m", "v1.3.0", "v1.3.0")
	fresh.Released = now.Add(-3 * day)
	if got := enforce(cooling, []module.Module{fresh}); len(got) != 0 {
		// A permitted version is no exception at all, whatever the cooldown says:
		// the cooldown withholds an upgrade, it does not indict the tree.
		t.Errorf("got %v, want nothing for a version the policy permits", got)
	}

	// The constraint refuses the version outright. The cooldown is irrelevant, so it
	// is not named: waiting it out would still leave the version refused.
	capped := gate(t, `{
      "actions": {"note": {"exit": 0, "log": "warn"}},
      "modules": {"example.com/m": {"allow": "<= 1.2.0"}},
      "rules":   [{"when": "local-policy-exception", "then": "note"}]
    }`)
	got := enforce(capped, []module.Module{fresh})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	if strings.Contains(got[0].Detail, "cooldown") {
		t.Errorf("detail %q names the cooldown, which waiting would not resolve", got[0].Detail)
	}
}

// TestAnnotateCooldownsExemptsAModuleFromTheWait checks the whole path the feature
// exists for: a policy names a project's own modules, and a release too fresh for the
// run's period is offered anyway.
//
// The unit tests cover the period being read and the predicate consulting it. This one
// covers them being connected, which is where the feature would silently do nothing.
func TestAnnotateCooldownsExemptsAModuleFromTheWait(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()
	module.SetCooldown(7 * day)
	defer module.SetCooldown(0)

	// As a project publishing its own modules would write it: the wildcard covers
	// everything under the organisation, and the run keeps its ordinary period.
	rules := gate(t, `{
      "actions": {"note": {"exit": 0, "log": "warn"}},
      "modules": {
        "github.com/opensearch-project/**": {"cooldown": "0"},
        "example.com/**":                   {"allow": "*"}
      },
      "rules": [{"when": "local-policy-exception", "then": "note"}]
    }`)

	// Both published three days ago, against a seven day period.
	ours := mustModule(t, "github.com/opensearch-project/opensearch-go/v5", "v5.0.0-rc4", "v5.0.0-rc5")
	ours.Released = now.Add(-3 * day)
	theirs := mustModule(t, "example.com/other", "v1.0.0", "v1.1.0")
	theirs.Released = now.Add(-3 * day)

	// Before the policy is applied, both are withheld: this is the bug being fixed.
	for _, m := range []module.Module{ours, theirs} {
		if !m.Cooling() {
			t.Fatalf("%s: want it cooling before the policy is applied", m.Name)
		}
	}

	modules := []module.Module{ours, theirs}
	annotateCooldowns(rules, modules)

	// Ours is exempt, so the fresh release is available at once.
	if modules[0].Cooling() {
		t.Errorf("%s: still cooling, want the policy's zero period to exempt it",
			modules[0].Name)
	}
	if got := modules[0].Remaining(); got != 0 {
		t.Errorf("%s: Remaining() = %v, want no wait", modules[0].Name, got)
	}
	// A module the policy set no period for keeps the run's, so the exemption is not
	// leaking into everything the policy happens to mention.
	if !modules[1].Cooling() {
		t.Errorf("%s: not cooling, want the run's period to still apply", modules[1].Name)
	}
	if got, want := modules[1].Remaining(), 4*day; got != want {
		t.Errorf("%s: Remaining() = %v, want %v", modules[1].Name, got, want)
	}
}

// TestAnnotateCooldownsLeavesSettleNothingToDo checks that a module a policy exempted is
// not put through the release-history walk.
//
// settle decides which histories to read by asking each module whether it is cooling, so
// an exempted module should present no work at all. This is what makes the annotation's
// position -- before settle rather than beside the archived marks -- observable.
func TestAnnotateCooldownsLeavesSettleNothingToDo(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	defer module.SetClock(func() time.Time { return now })()
	module.SetCooldown(7 * day)
	defer module.SetCooldown(0)

	rules := gate(t, `{
      "actions": {"note": {"exit": 0, "log": "warn"}},
      "modules": {"github.com/acme/**": {"cooldown": "0"}},
      "rules":   [{"when": "local-policy-exception", "then": "note"}]
    }`)

	fresh := mustModule(t, "github.com/acme/lib", "v1.0.0", "v1.1.0")
	fresh.Released = now.Add(-1 * time.Hour)
	modules := []module.Module{fresh}
	annotateCooldowns(rules, modules)

	// settle only reads histories for the modules that are cooling. None are, so it
	// returns without running any command -- which is why a context that would fail
	// any subprocess is safe to pass, and proves none was started.
	app := &AppEnv{churn: 30 * day}
	candidates, err := app.settle(t.Context(), t.TempDir(), modules)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if len(candidates) != 0 {
		t.Errorf("candidates = %v, want none for a module exempt from the wait", candidates)
	}
	if modules[0].Stepped() {
		t.Error("the module stepped back, want the newest release taken as it stands")
	}
}
