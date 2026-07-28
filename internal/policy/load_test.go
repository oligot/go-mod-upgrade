package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts a policy file in a temporary directory and returns its path.
func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// A security-managed baseline: nothing is permitted unless named.
const baseline = `{
  "actions": {
    "fail": {"exit": 1},
    "warn": {"exit": 0, "log": "warn"}
  },
  "modules": {
    "**":              {"deny": "*"},
    "golang.org/x/**": {"allow": ">= v0.30.0"}
  },
  "rules": [
    {"when": "vuln-reachable", "then": "fail"},
    {"when": "vuln-present",   "then": "warn"},
    {"when": "denied",         "then": "fail"},
    {"when": "version-denied", "then": "fail"}
  ]
}`

// A project's own additions, layered on the baseline.
const project = `{
  "modules": {
    "github.com/rs/zerolog": {"allow": "go.mod"},
    "golang.org/x/text":     {"allow": ">= v0.40.0"}
  }
}`

func TestLoadMerges(t *testing.T) {
	dir := t.TempDir()
	base := write(t, dir, "baseline.json", baseline)
	proj := write(t, dir, "project.json", project)

	p, err := Load([]string{base, proj})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The project's own module is permitted.
	if pattern, found := p.Lookup("github.com/rs/zerolog"); !found {
		t.Error("the project's module is not covered by the merged policy")
	} else if pattern != "github.com/rs/zerolog" {
		t.Errorf("matched %q, want the project's own rule", pattern)
	}

	// A later file tightening an earlier one governs.
	if d := p.Check("golang.org/x/text", ver(t, "v0.35.0"), nil); d.Verdict != VersionDenied {
		t.Errorf("got %s under %q, want the project's tighter floor", d.Verdict, d.Pattern)
	}

	// The baseline still refuses everything neither file names.
	if d := p.Check("example.com/sneaked-in", ver(t, "v1.0.0"), nil); d.Verdict != Denied {
		t.Errorf("got %s, want the baseline default to refuse it", d.Verdict)
	}

	// Actions and conditions survive the merge.
	action, ok := p.Action(CondVulnReachable)
	if !ok {
		t.Fatal("no action for a reachable advisory")
	}
	if !action.Fails() {
		t.Errorf("action %q does not fail the run, want it to", action.Name)
	}
	if warn, ok := p.Action(CondVulnPresent); !ok || warn.Fails() {
		t.Errorf("a present-only advisory got %+v, want a non-failing action", warn)
	}
}

// TestLoadScansVulnerabilities checks that a policy asking about advisories
// says so, since the caller should not have to keep a flag in step with the
// contents of a file it did not write.
func TestLoadScansVulnerabilities(t *testing.T) {
	dir := t.TempDir()

	wants := write(t, dir, "wants.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "vuln-reachable", "then": "fail"}]
    }`)
	p, err := Load([]string{wants})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !p.ScansVulnerabilities() {
		t.Error("a policy naming a vuln condition does not ask for a scan")
	}

	versionsOnly := write(t, dir, "versions.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": ">= v1.0.0"}},
      "rules":   [{"when": "version-denied", "then": "fail"}]
    }`)
	q, err := Load([]string{versionsOnly})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if q.ScansVulnerabilities() {
		t.Error("a policy about versions alone asks for a scan, and its cost")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		says string
	}{
		{
			name: "unknown condition",
			body: `{"actions":{"fail":{"exit":1}},"rules":[{"when":"bogus","then":"fail"}]}`,
			says: "bogus",
		},
		{
			// A condition pointing at an action nobody defined would silently
			// do nothing, which in a policy is worse than refusing to run.
			name: "condition names an undefined action",
			body: `{"actions":{"fail":{"exit":1}},"rules":[{"when":"denied","then":"explode"}]}`,
			says: "explode",
		},
		{
			name: "unknown module action",
			body: `{"modules":{"**":{"permit":"*"}}}`,
			says: "permit",
		},
		{
			name: "unparseable constraint",
			body: `{"modules":{"example.com/x":{"allow":"not a version"}}}`,
			says: "example.com/x",
		},
		{
			// A typo in a security policy should stop the run, not be ignored.
			name: "unknown top-level key",
			body: `{"moduls":{"**":{"allow":"*"}}}`,
			says: "moduls",
		},
		{
			// A policy with no rules can only pass, whatever it says about
			// modules, and a security file must not fail open.
			name: "no rules at all",
			body: `{"modules":{"**":{"deny":"*"}}}`,
			says: "no rules",
		},
		{
			name: "malformed json",
			body: `{"modules":`,
			says: "policy",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := write(t, t.TempDir(), "policy.json", c.body)
			_, err := Load([]string{path})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("error %q does not mention %q", err, c.says)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load([]string{filepath.Join(t.TempDir(), "absent.json")})
	if err == nil {
		t.Fatal("expected an error for a file that does not exist")
	}
	if !strings.Contains(err.Error(), "absent.json") {
		t.Errorf("error %q does not name the file", err)
	}
}

// TestLoadDefaultExit checks that an action without an explicit status still
// fails, since an action exists to have an effect.
func TestLoadDefaultExit(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"fail": {}},
      "modules": {"**": {"deny": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	action, ok := p.Action(CondDenied)
	if !ok {
		t.Fatal("no action for a denied module")
	}
	if !action.Fails() {
		t.Errorf("exit = %d, want a failing status by default", action.Exit)
	}
}

// TestVerdictNamesCondition checks that a verdict reports itself as the
// condition a rule responds to, so a decision needs no translation.
func TestVerdictNamesCondition(t *testing.T) {
	for verdict, want := range map[Verdict]string{
		NotAllowed:    CondNotAllowed,
		Denied:        CondDenied,
		VersionDenied: CondVersionDenied,
	} {
		if got := verdict.String(); got != want {
			t.Errorf("verdict %d reports %q, want the condition %q", verdict, got, want)
		}
	}
}

// TestLoadRulesMayComeFromAnotherFile checks that an overlay naming only the
// modules it adds is usable, since the rules live in the baseline it is merged
// with.
func TestLoadRulesMayComeFromAnotherFile(t *testing.T) {
	dir := t.TempDir()
	base := write(t, dir, "baseline.json", baseline)
	overlay := write(t, dir, "overlay.json", `{
      "modules": {"example.com/added": {"allow": "*"}}
    }`)

	p, err := Load([]string{base, overlay})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := p.Action(CondVulnReachable); !ok {
		t.Error("the baseline's rules did not survive the merge")
	}
	if d := p.Check("example.com/added", ver(t, "v1.0.0"), nil); d.Verdict != Allowed {
		t.Errorf("the overlay's module got %s, want allowed", d.Verdict)
	}

	// On its own it has nothing to act on, so it is refused.
	if _, err := Load([]string{overlay}); err == nil {
		t.Error("an overlay alone was accepted, want it refused for having no rules")
	}
}
