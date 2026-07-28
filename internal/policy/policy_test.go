package policy

import (
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
)

// TestLookupSpecificity checks that the most specific pattern decides, so a
// policy does not depend on the order its rules were added.
func TestLookupSpecificity(t *testing.T) {
	p := New()
	for _, r := range []struct{ pattern, allow string }{
		// Added least specific first, so a naive implementation that keeps the
		// last match would get these wrong.
		{"**", "*"},
		{"golang.org/x/**", ">= v0.30.0"},
		{"golang.org/x/text", ">= v0.40.0"},
		{"github.com/*/aws-sdk-go", "*"},
	} {
		if err := p.Add(r.pattern, Mark{Allow: r.allow}); err != nil {
			t.Fatalf("Add(%q): %v", r.pattern, err)
		}
	}

	cases := []struct {
		path string
		want string
	}{
		// An exact path beats a pattern that also covers it.
		{"golang.org/x/text", "golang.org/x/text"},
		// A deeper path still falls to the rule governing its prefix.
		{"golang.org/x/text/unicode/norm", "golang.org/x/text"},
		{"golang.org/x/sys", "golang.org/x/**"},
		// A wildcard in the middle of a path matches.
		{"github.com/aws/aws-sdk-go", "github.com/*/aws-sdk-go"},
		// Anything else falls to the root, which is where a policy states its
		// default.
		{"example.com/unlisted", "**"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, found := p.Lookup(c.path)
			if !found {
				t.Fatalf("no rule matched %q", c.path)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestLookupOrderIndependent checks that adding the same rules in the opposite
// order reaches the same answer, since a policy assembled from several files
// must not depend on which file happened to come first.
func TestLookupOrderIndependent(t *testing.T) {
	patterns := []string{"**", "golang.org/x/**", "golang.org/x/text"}

	forward := New()
	for _, pattern := range patterns {
		if err := forward.Add(pattern, Mark{Allow: "*"}); err != nil {
			t.Fatalf("Add(%q): %v", pattern, err)
		}
	}
	backward := New()
	for i := len(patterns) - 1; i >= 0; i-- {
		if err := backward.Add(patterns[i], Mark{Allow: "*"}); err != nil {
			t.Fatalf("Add(%q): %v", patterns[i], err)
		}
	}

	for _, path := range []string{
		"golang.org/x/text",
		"golang.org/x/sys",
		"example.com/other",
	} {
		f, _ := forward.Lookup(path)
		b, _ := backward.Lookup(path)
		if f != b {
			t.Errorf("%s matched %q one way and %q the other", path, f, b)
		}
	}
}

// TestLookupNothingPermitted checks that an empty policy permits nothing, which
// is the posture a security-managed allow-list starts from.
func TestLookupNothingPermitted(t *testing.T) {
	if _, found := New().Lookup("golang.org/x/text"); found {
		t.Error("an empty policy matched a module, want nothing permitted")
	}
}

// TestAddRejectsBadConstraint checks that an unusable constraint is refused
// when the policy is read, rather than silently permitting or denying later.
func TestAddRejectsBadConstraint(t *testing.T) {
	p := New()
	err := p.Add("golang.org/x/text", Mark{Allow: "not a version"})
	if err == nil {
		t.Fatal("expected an error for an unparseable constraint")
	}
	// The message has to name the pattern, since a policy may hold many.
	if got := err.Error(); !strings.Contains(got, "golang.org/x/text") {
		t.Errorf("error %q does not name the pattern", got)
	}
}

// ver parses a version for a test, failing if it is unusable.
func ver(t *testing.T, v string) *semver.Version {
	t.Helper()
	parsed, err := semver.NewVersion(v)
	if err != nil {
		t.Fatalf("parsing %q: %v", v, err)
	}
	return parsed
}

// TestCheckVerdicts covers the conclusions a policy can reach, since each one
// calls for a different fix.
func TestCheckVerdicts(t *testing.T) {
	p := New()
	mustAdd(t, p, "**", "", "*")                        // deny by default
	mustAdd(t, p, "golang.org/x/**", ">= v0.30.0", "")  // allowed above a floor
	mustAdd(t, p, "example.com/pinned", "= v1.2.3", "") // allowed at one version
	mustAdd(t, p, "example.com/banned", "", "*")        // refused outright

	cases := []struct {
		name    string
		module  string
		version string
		want    Verdict
	}{
		{"above the floor", "golang.org/x/text", "v0.40.0", Allowed},
		{"below the floor", "golang.org/x/text", "v0.20.0", VersionDenied},
		{"at the pin", "example.com/pinned", "v1.2.3", Allowed},
		{"off the pin", "example.com/pinned", "v1.2.4", VersionDenied},
		{"refused outright", "example.com/banned", "v1.0.0", Denied},
		// The explicit default refuses it, which is a rule doing its job
		// rather than an absence of one.
		{"caught by the default", "example.com/unknown", "v1.0.0", Denied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := p.Check(c.module, ver(t, c.version), nil)
			if d.Verdict != c.want {
				t.Errorf("got %s, want %s (rule %q)", d.Verdict, c.want, d.Pattern)
			}
		})
	}
}

// TestCheckNotAllowedVersusDenied separates the two ways a module ends up
// unpermitted, since they call for different fixes: one needs a rule added, the
// other needs the rule that refused it reconsidered.
func TestCheckNotAllowedVersusDenied(t *testing.T) {
	// A policy that states its posture refuses what it does not name.
	stated := New()
	mustAdd(t, stated, "**", "", "*")
	if d := stated.Check("example.com/x", ver(t, "v1.0.0"), nil); d.Verdict != Denied {
		t.Errorf("got %s, want denied by the stated default", d.Verdict)
	}

	// A policy that names only what it allows leaves the rest uncovered.
	partial := New()
	mustAdd(t, partial, "golang.org/x/**", "*", "")
	if d := partial.Check("example.com/x", ver(t, "v1.0.0"), nil); d.Verdict != NotAllowed {
		t.Errorf("got %s, want not-allowed where no rule covers the module", d.Verdict)
	}
}

// TestCheckFromGoMod checks that a rule can defer to go.mod rather than
// repeating a version that would then have to be kept in step.
func TestCheckFromGoMod(t *testing.T) {
	p := New()
	mustAdd(t, p, "golang.org/x/text", FromGoMod, "")

	required := ver(t, "v0.4.0")
	if d := p.Check("golang.org/x/text", ver(t, "v0.4.0"), required); d.Verdict != Allowed {
		t.Errorf("the version go.mod records got %s, want allowed", d.Verdict)
	}
	// Anything else is a drift between the policy's source of truth and what
	// is actually in use.
	if d := p.Check("golang.org/x/text", ver(t, "v0.5.0"), required); d.Verdict != VersionDenied {
		t.Errorf("a version go.mod does not record got %s, want version-denied", d.Verdict)
	}
	// With nothing recorded there is nothing to defer to.
	if d := p.Check("golang.org/x/text", ver(t, "v0.4.0"), nil); d.Verdict != VersionDenied {
		t.Errorf("no recorded version got %s, want version-denied", d.Verdict)
	}
}

// TestCheckLayeredPolicies checks the arrangement this feature exists for: a
// security-managed baseline that denies by default, with a project adding what
// it needs on top.
func TestCheckLayeredPolicies(t *testing.T) {
	p := New()
	// The corporate baseline, read first.
	mustAdd(t, p, "**", "", "*")
	mustAdd(t, p, "golang.org/x/**", ">= v0.30.0", "")
	// The project's own file, read after, naming what it additionally needs.
	mustAdd(t, p, "github.com/rs/zerolog", ">= v1.34.0", "")
	// And tightening one the baseline had allowed more loosely.
	mustAdd(t, p, "golang.org/x/text", ">= v0.40.0", "")

	if d := p.Check("github.com/rs/zerolog", ver(t, "v1.35.1"), nil); d.Verdict != Allowed {
		t.Errorf("a module the project added got %s, want allowed", d.Verdict)
	}
	// The later, more specific rule governs.
	if d := p.Check("golang.org/x/text", ver(t, "v0.35.0"), nil); d.Verdict != VersionDenied {
		t.Errorf("got %s under rule %q, want the project's tighter floor to apply",
			d.Verdict, d.Pattern)
	}
	// The baseline still governs everything the project did not name.
	if d := p.Check("example.com/sneaked-in", ver(t, "v1.0.0"), nil); d.Verdict == Allowed {
		t.Error("a module no rule names was allowed, want the default to deny")
	}
}

// TestCheckDenyBeatsAllow checks that naming a module in both places refuses
// it, rather than leaving the outcome to which field was read first.
func TestCheckDenyBeatsAllow(t *testing.T) {
	p := New()
	mustAdd(t, p, "example.com/both", "*", "*")

	if d := p.Check("example.com/both", ver(t, "v1.0.0"), nil); d.Verdict != Denied {
		t.Errorf("got %s, want denied", d.Verdict)
	}
}

// TestCheckReportsTheRule checks that a decision names what decided it, since a
// policy assembled from several files is otherwise hard to debug.
func TestCheckReportsTheRule(t *testing.T) {
	p := New()
	mustAdd(t, p, "golang.org/x/**", ">= v0.30.0", "")

	d := p.Check("golang.org/x/text", ver(t, "v0.20.0"), nil)
	if d.Pattern != "golang.org/x/**" {
		t.Errorf("pattern = %q, want the rule that decided", d.Pattern)
	}
	if d.Constraint != ">= v0.30.0" {
		t.Errorf("constraint = %q, want the expression the version was measured against", d.Constraint)
	}
	if d.Module != "golang.org/x/text" {
		t.Errorf("module = %q, want the module decided upon", d.Module)
	}
}

func mustAdd(t *testing.T, p *Policy, pattern, allow, deny string) {
	t.Helper()
	if err := p.Add(pattern, Mark{Allow: allow, Deny: deny}); err != nil {
		t.Fatalf("Add(%q): %v", pattern, err)
	}
}

// TestAddKeepsArchivedAcrossFiles pins the arrangement an archived.json exists
// for: the mark is asserted in its own file and survives everything stacked
// after it.
//
// This is the case that would otherwise fail open. --format=policy regenerates
// an "allow" for every module, so an overlay produced that way names the same
// patterns an archived file does. Replacing the whole rule per pattern would
// drop the attestation exactly when a project refreshes its allow-list, and
// nothing in the output would say so.
func TestAddKeepsArchivedAcrossFiles(t *testing.T) {
	p := New()
	// The archived file, asserting a fact about the module.
	if err := p.Add("example.com/gone", Mark{
		Archived: "unmaintained since 2018",
	}); err != nil {
		t.Fatalf("Add archived: %v", err)
	}
	// A regenerated allow-list, naming the same module and saying only that it
	// is permitted.
	if err := p.Add("example.com/gone", Mark{Allow: FromGoMod}); err != nil {
		t.Fatalf("Add allow: %v", err)
	}

	reason, ok := p.Archived("example.com/gone")
	if !ok {
		t.Fatal("the archived mark was lost behind a regenerated allow-list")
	}
	if reason != "unmaintained since 2018" {
		t.Errorf("reason = %q, want the asserted one", reason)
	}
}

// TestAddArchivedIsOrderIndependent checks the mark survives whichever way the
// files are stacked, since --policy takes them in whatever order the caller
// names and an attestation must not depend on that.
func TestAddArchivedIsOrderIndependent(t *testing.T) {
	for _, c := range []struct {
		name  string
		marks []Mark
	}{
		{"archived first", []Mark{{Archived: "gone"}, {Allow: FromGoMod}}},
		{"archived last", []Mark{{Allow: FromGoMod}, {Archived: "gone"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := New()
			for _, m := range c.marks {
				if err := p.Add("example.com/gone", m); err != nil {
					t.Fatalf("Add: %v", err)
				}
			}
			if _, ok := p.Archived("example.com/gone"); !ok {
				t.Error("the archived mark did not survive this order")
			}
			// The permission has to survive too, or stacking the mark would
			// deny the module instead.
			if d := p.Check("example.com/gone", ver(t, "v1.0.0"), ver(t, "v1.0.0")); d.Verdict != Allowed {
				t.Errorf("verdict = %s, want the allow to still stand", d.Verdict)
			}
		})
	}
}

// TestAddReplacesPermissionAsOnePiece checks that allow and deny move together.
//
// They are two halves of one statement about what is permitted, so a later file
// restating a pattern's permission replaces both. Merging them field by field
// would leave a baseline's deny standing under a project's allow, which reads as
// the project having permitted something it did not.
func TestAddReplacesPermissionAsOnePiece(t *testing.T) {
	p := New()
	mustAdd(t, p, "example.com/m", "", "*") // baseline refuses it
	mustAdd(t, p, "example.com/m", "*", "") // a later file permits it

	if d := p.Check("example.com/m", ver(t, "v1.0.0"), nil); d.Verdict != Allowed {
		t.Errorf("verdict = %s, want the later permission to replace the earlier", d.Verdict)
	}
}

// TestActionStatus checks the status an action actually produces, since a
// process status is a single byte and a policy meaning to fail must not be able
// to pass by asking for a value that wraps to zero.
func TestActionStatus(t *testing.T) {
	cases := []struct {
		name string
		exit int
		want int
	}{
		{"success", 0, 0},
		{"the usual failure", 1, 1},
		{"a chosen status", 42, 42},
		{"the largest status", 255, 255},
		// A shell reports -1 as 255, so that is what the policy gets.
		{"negative wraps", -1, 255},
		{"further negative", -2, 254},
		// These would wrap to zero, which would turn a refusal into a pass.
		{"256 would wrap to zero", 256, 1},
		{"512 would wrap to zero", 512, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := Action{Name: "test", Exit: c.exit}
			if got := a.Status(); got != c.want {
				t.Errorf("Action{Exit: %d}.Status() = %d, want %d", c.exit, got, c.want)
			}
			// Anything the policy did not call success has to fail.
			if wantFails := c.exit != 0; a.Fails() != wantFails {
				t.Errorf("Fails() = %v, want %v", a.Fails(), wantFails)
			}
			if a.Fails() && a.Status() == 0 {
				t.Error("an action that fails produced a successful status")
			}
		})
	}
}
