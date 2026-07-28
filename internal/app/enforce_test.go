package app

import (
	"os"
	"strings"
	"testing"

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

// TestEnforceVersionDenied checks that a module a rule covers but whose version
// falls outside it is reported as needing to move, not as needing a rule.
func TestEnforceVersionDenied(t *testing.T) {
	p := gate(t, `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"example.com/pinned": {"allow": ">= v2.0.0"}},
      "rules":   [{"when": "version-denied", "then": "fail"}]
    }`)

	got := enforce(p, []module.Module{mustModule(t, "example.com/pinned", "v1.0.0", "v1.0.1")})
	if len(got) != 1 {
		t.Fatalf("got %d violations, want 1", len(got))
	}
	if got[0].Condition != policy.CondVersionDenied {
		t.Errorf("condition = %q, want %q", got[0].Condition, policy.CondVersionDenied)
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

// TestReportStatus checks that the status left behind is the highest any action
// asked for, so a warning alongside a failure still fails.
func TestReportStatus(t *testing.T) {
	fail := policy.Action{Name: "fail", Exit: 1}
	halt := policy.Action{Name: "halt", Exit: 42}
	warn := policy.Action{Name: "warn", Exit: 0}

	cases := []struct {
		name string
		in   []violation
		want int
	}{
		{"nothing to report", nil, 0},
		{"a warning alone", []violation{{Action: warn}}, 0},
		{"a failure", []violation{{Action: fail}}, 1},
		{"a warning does not mask a failure", []violation{{Action: warn}, {Action: fail}}, 1},
		{"the highest status wins", []violation{{Action: fail}, {Action: halt}}, 42},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := report(c.in); got != c.want {
				t.Errorf("report() = %d, want %d", got, c.want)
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
	if left := upgradable([]module.Module{ignored}); len(left) != 0 {
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
	if left := upgradable([]module.Module{current, vulnerable}); len(left) != 0 {
		t.Errorf("got %d upgradable, want a current module withheld", len(left))
	}
}
