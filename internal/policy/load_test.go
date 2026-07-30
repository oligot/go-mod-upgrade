package policy

import (
	"os"
	"path/filepath"
	"slices"
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
			// An assertion the toolchain cannot check is only reviewable if it
			// says why, so a bare mark is refused.
			name: "archived without a reason",
			body: `{"actions":{"warn":{"exit":0}},"modules":{"example.com/x":{"archived":""}},"rules":[{"when":"archived","then":"warn"}]}`,
			says: "reason",
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

// An archived file, maintained on its own and stacked with everything else. It
// asserts facts and leaves the response to whatever it is merged with.
const archived = `{
  "modules": {
    "github.com/dgrijalva/jwt-go": {
      "archived": "unmaintained since 2018; migrate to golang-jwt/jwt"
    }
  },
  "rules": [
    {"when": "archived", "then": "warn"}
  ]
}`

// TestLoadStacksArchivedFile checks the arrangement archived.json exists for: a
// baseline, an archived file, and a regenerated allow-list, in that order.
//
// The allow-list is the hazard. --format=policy writes an "allow" for every
// module, so it restates the same patterns the archived file named. The mark has
// to survive that, or refreshing an allow-list would quietly drop the very
// annotation the archived file is distributed to carry.
func TestLoadStacksArchivedFile(t *testing.T) {
	dir := t.TempDir()
	base := write(t, dir, "baseline.json", baseline)
	arch := write(t, dir, "archived.json", archived)
	// As --format=policy would produce it: every module, deferring to go.mod.
	generated := write(t, dir, "allow-list.json", `{
      "modules": {
        "github.com/dgrijalva/jwt-go": {"allow": "go.mod"},
        "github.com/rs/zerolog":       {"allow": "go.mod"}
      }
    }`)

	p, err := Load([]string{base, arch, generated})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	reason, ok := p.Archived("github.com/dgrijalva/jwt-go")
	if !ok {
		t.Fatal("the archived mark was lost behind the regenerated allow-list")
	}
	if !strings.Contains(reason, "golang-jwt/jwt") {
		t.Errorf("reason = %q, want the one the archived file gave", reason)
	}
	// The generated permission still applies, so stacking the mark does not
	// deny the module.
	if d := p.Check("github.com/dgrijalva/jwt-go", ver(t, "v3.2.0"), ver(t, "v3.2.0")); d.Verdict != Allowed {
		t.Errorf("verdict = %s, want the allow-list's permission to stand", d.Verdict)
	}
	// A module the archived file said nothing about carries no mark.
	if _, ok := p.Archived("github.com/rs/zerolog"); ok {
		t.Error("an unmarked module reported as archived")
	}
	// The archived file may carry its own rule, so the merged policy acts on it.
	if _, ok := p.Action(CondArchived); !ok {
		t.Error("no action for an archived module")
	}
}

// TestLoadArchivedNeedsNoScan checks that asserting a module is abandoned does
// not turn on the vulnerability scan, since the assertion comes from the file
// rather than the database.
func TestLoadArchivedNeedsNoScan(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"warn": {"exit": 0}},
      "modules": {"example.com/x": {"archived": "abandoned"}},
      "rules":   [{"when": "archived", "then": "warn"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.ScansVulnerabilities() {
		t.Error("an archived rule asked for a vulnerability scan, want none")
	}
}

// TestLoadTags checks that a policy can name the build configurations to analyse,
// so a caller running it needs only to name the policy.
func TestLoadTags(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "tags":    ["+integration && core", "-multinode"],
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"deny": "*"}},
      "rules":   [{"when": "vuln-reachable", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"+integration && core", "-multinode"}
	if got := p.Tags(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestLoadTagsAccumulate checks that stacked policies contribute their
// configurations rather than the last file winning.
//
// A baseline naming the integration build and an overlay naming another both want
// covering: neither is stating a preference between them, so dropping one would
// silently narrow the analysis.
func TestLoadTagsAccumulate(t *testing.T) {
	dir := t.TempDir()
	base := write(t, dir, "baseline.json", `{
      "tags":    ["+integration"],
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"deny": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	overlay := write(t, dir, "overlay.json", `{
      "tags":    ["+plugins", "+integration"],
      "modules": {"example.com/m": {"allow": "*"}}
    }`)

	p, err := Load([]string{base, overlay})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The duplicate is not repeated: naming a configuration twice asks for it once.
	want := []string{"+integration", "+plugins"}
	if got := p.Tags(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestLoadNoTags checks that a policy saying nothing about configurations leaves
// the choice to whatever the project declares.
func TestLoadNoTags(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"deny": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := p.Tags(); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}
