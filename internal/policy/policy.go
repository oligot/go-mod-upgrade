// Package policy decides whether the modules a project depends on are
// permitted, and what should happen when they are not.
//
// A policy is a set of rules anchored to module paths, plus the actions to take
// when a condition is met. Nothing is permitted unless a rule says so, which
// makes a policy an allow-list: a security-managed baseline can deny everything
// and name what is allowed, and a project can add what it needs on top.
package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// FromGoMod is the constraint meaning "whatever version go.mod records".
//
// go.mod is itself a reviewed document, so a policy can defer to it rather than
// repeating a version that would then need to be kept in step.
const FromGoMod = "go.mod"

// Wildcards usable in place of a path segment.
const (
	// One matches any single segment.
	One = "*"
	// Rest matches every remaining segment, so "**" alone matches everything
	// and is how a policy states its default.
	Rest = "**"
)

// Verdict is what a policy has to say about one module.
type Verdict int

const (
	// NotAllowed means no rule matched the module at all, so nothing has
	// permitted it. The fix is to add a rule.
	NotAllowed Verdict = iota
	// VersionDenied means a rule matched but the version failed its
	// constraint. The fix is to move the module, not the policy.
	VersionDenied
	// Allowed means a rule matched and the version satisfied it.
	Allowed
	// Denied means a rule matched and explicitly refused the module.
	Denied
)

// String returns the verdict as the condition a rule responds to, so a
// decision can be looked up without a translation table.
func (v Verdict) String() string {
	switch v {
	case NotAllowed:
		return CondNotAllowed
	case VersionDenied:
		return CondVersionDenied
	case Allowed:
		return "allowed"
	case Denied:
		return CondDenied
	default:
		return "unknown"
	}
}

// rule is what a policy says about the paths matching one pattern.
type rule struct {
	// allow and deny hold the constraints for each action, either a semver
	// range or FromGoMod. A nil constraint with fromGoMod set means the
	// version is taken from go.mod.
	allow, deny *constraint
	// archived carries the reason a human gave for considering the module
	// abandoned, empty when none has. Unlike everything else here it is an
	// assertion rather than an observation: the toolchain cannot confirm or
	// refute it, so the reason is kept for a reviewer to weigh.
	archived string
	// pattern is kept for reporting which rule decided a module.
	pattern string
}

// Mark is what one policy file says about the paths matching one pattern.
//
// The fields are separate statements, so a file may set any subset and leave the
// rest to whatever else is stacked. Allow and Deny are the exception: they are
// two halves of one statement about what is permitted, and move together.
type Mark struct {
	// Allow and Deny are version constraints, either a semver range or
	// FromGoMod.
	Allow, Deny string
	// Archived is the reason a human gave for considering the module abandoned.
	Archived string
}

// constraint is a version range, or a deferral to go.mod.
type constraint struct {
	versions  *semver.Constraints
	fromGoMod bool
	text      string
}

// parseConstraint reads a constraint expression. Comma-separated ranges are
// combined with AND, which is what semver.NewConstraint already does.
func parseConstraint(expr string) (*constraint, error) {
	expr = strings.TrimSpace(expr)
	if expr == FromGoMod {
		return &constraint{fromGoMod: true, text: expr}, nil
	}
	cs, err := semver.NewConstraint(expr)
	if err != nil {
		return nil, fmt.Errorf("constraint %q: %w", expr, err)
	}
	return &constraint{versions: cs, text: expr}, nil
}

// allows reports whether a version satisfies the constraint. A constraint
// deferring to go.mod accepts whatever go.mod recorded, which the caller has
// already resolved into required.
func (c *constraint) allows(version, required *semver.Version) bool {
	if c == nil {
		return false
	}
	if c.fromGoMod {
		return required != nil && version.Equal(required)
	}
	return c.versions.Check(release(version))
}

// release returns the version with any prerelease dropped, which is what a
// constraint here is measured against.
//
// Semver excludes a prerelease from an ordinary range, on the grounds that
// nobody resolving ">= v1.2.0" wants an untested v1.3.0-rc1 selected for them.
// That reasoning is about choosing a version to move to. This policy asks a
// different question -- whether the version already in use is permitted -- and
// for that the exclusion is simply wrong: Go writes a commit pin as
// "v0.0.0-20180909062703-3050d21c67d7" and a withdrawn release as
// "v0.1.1-deprecated", both prereleases in form and neither a candidate for
// anything. Left as semver intends, a rule as permissive as "*" would refuse
// modules that a real tree very likely contains, which makes the constraint
// language unable to say "anything".
//
// So the prerelease is dropped and the release part compared, which keeps every
// version ordered where it belongs: the commit pin above stands at v0.0.0, below
// any real floor. A policy that means to exclude prereleases can bound the range
// it asks for.
func release(version *semver.Version) *semver.Version {
	if version.Prerelease() == "" {
		return version
	}
	base := *semver.New(version.Major(), version.Minor(), version.Patch(), "", version.Metadata())
	return &base
}

// node is one segment of a module path, holding any rule anchored there.
type node struct {
	children map[string]*node
	rule     *rule
}

// Policy decides what is permitted. The zero value permits nothing, which is
// the posture a policy is meant to start from.
type Policy struct {
	root *node
	// actions maps a name to what it does, so what "fail" means is stated
	// once rather than repeated at every rule.
	actions map[string]Action
	// conditions maps a condition to the action taken when it is met.
	conditions map[string]string
	// tags names the build configurations to analyse, as the files gave them.
	// Later files add to the list rather than replacing it, since each is stating
	// a configuration it cares about.
	tags []string
	// cooldown is how long a release must settle before it is recommended, and
	// churn the window over which repeated releasing is detected. Nil when no file
	// said, which leaves the choice to the caller rather than asserting zero.
	cooldown *time.Duration
	churn    *time.Duration
	// goReleases is how many Go releases the project supports, nil when no file said.
	goReleases *int
}

// GoReleases returns how many Go releases the policy supports, and whether any file
// said.
//
// A count rather than a version, so the floor it implies moves when Go releases and the
// policy does not have to be edited every six months.
func (p *Policy) GoReleases() (int, bool) {
	if p.goReleases == nil {
		return 0, false
	}
	return *p.goReleases, true
}

// Cooldown returns how long the policy asks a release to settle before it is
// recommended, and whether any file said.
//
// The second result matters: zero is a meaningful answer, disabling the cooldown,
// and must not be confused with the policy having no opinion.
func (p *Policy) Cooldown() (time.Duration, bool) {
	if p.cooldown == nil {
		return 0, false
	}
	return *p.cooldown, true
}

// Churn returns the window over which the policy asks repeated releasing to be
// detected, and whether any file said.
func (p *Policy) Churn() (time.Duration, bool) {
	if p.churn == nil {
		return 0, false
	}
	return *p.churn, true
}

// Tags returns the build configurations the policy asks to be analysed, in the
// order the files named them.
func (p *Policy) Tags() []string { return slices.Clone(p.tags) }

// Action is what happens when a condition is met.
type Action struct {
	// Name is the key the policy gave this action.
	Name string
	// Exit is the status to leave with, as the policy wrote it.
	Exit int
	// Log names the level to report at, one of "error", "warn" or "info".
	Log string
}

// Status returns the exit status this action will actually produce.
//
// A process status is a single byte, so anything outside 0-255 is taken modulo
// 256 by the operating system: a policy asking to exit -1 is observed as 255. A
// value that wrapped to zero would otherwise turn a refusal into a pass, so it
// is reported as a failure instead.
func (a Action) Status() int {
	if a.Exit == 0 {
		return 0
	}
	status := ((a.Exit % 256) + 256) % 256
	if status == 0 {
		// The policy meant to fail, and 256 alone would not say so.
		return 1
	}
	return status
}

// Fails reports whether the action ends the run unsuccessfully.
func (a Action) Fails() bool { return a.Exit != 0 }

// New returns an empty policy, which permits nothing.
func New() *Policy {
	return &Policy{
		root:       &node{},
		actions:    map[string]Action{},
		conditions: map[string]string{},
	}
}

// Add anchors a mark at a pattern, merging it with whatever is already there.
//
// Merging is per field, which is what lets an assertion be distributed in its own
// file: an allow-list regenerated by --format=policy names every module it
// permits, and must not erase an archived mark it happens to restate. Allow and
// Deny are one statement about permission, so a mark setting either replaces
// both.
func (p *Policy) Add(pattern string, m Mark) error {
	cur := p.root
	for seg := range strings.SplitSeq(pattern, "/") {
		if cur.children == nil {
			cur.children = map[string]*node{}
		}
		if cur.children[seg] == nil {
			cur.children[seg] = &node{}
		}
		cur = cur.children[seg]
	}
	if cur.rule == nil {
		cur.rule = &rule{}
	}
	r := cur.rule
	// The pattern is restated rather than assumed equal: the same node is
	// reached by the same pattern, so this is where it is recorded first.
	r.pattern = pattern

	if m.Allow != "" || m.Deny != "" {
		allow, deny := (*constraint)(nil), (*constraint)(nil)
		if m.Allow != "" {
			c, err := parseConstraint(m.Allow)
			if err != nil {
				return fmt.Errorf("pattern %q: %w", pattern, err)
			}
			allow = c
		}
		if m.Deny != "" {
			c, err := parseConstraint(m.Deny)
			if err != nil {
				return fmt.Errorf("pattern %q: %w", pattern, err)
			}
			deny = c
		}
		r.allow, r.deny = allow, deny
	}
	if m.Archived != "" {
		r.archived = m.Archived
	}
	return nil
}

// Archived reports the reason a module is marked abandoned, and whether any
// policy said so.
//
// The most specific pattern decides, as it does for permission, so a mark on an
// exact path outranks one covering a whole host.
func (p *Policy) Archived(path string) (reason string, found bool) {
	r, _ := p.lookup(p.root, strings.Split(path, "/"), 0)
	if r == nil || r.archived == "" {
		return "", false
	}
	return r.archived, true
}

// Lookup returns the rule governing a module path.
//
// The most specific pattern wins. Specificity is scored per segment, a literal
// counting for more than a wildcard, so an exact path always outranks a pattern
// that merely covers it and there is no ambiguity to resolve by ordering.
func (p *Policy) Lookup(path string) (pattern string, found bool) {
	r, _ := p.lookup(p.root, strings.Split(path, "/"), 0)
	if r == nil {
		return "", false
	}
	return r.pattern, true
}

// Decision is what a policy concluded about one module.
type Decision struct {
	// Module is the path decided upon.
	Module string
	// Verdict is the conclusion reached.
	Verdict Verdict
	// Pattern names the rule that decided, empty when none matched.
	Pattern string
	// Constraint is the expression the version was measured against, empty
	// when no rule matched.
	Constraint string
}

// Check decides whether a module at a version is permitted.
//
// required is the version go.mod records for the module, which a rule deferring
// to go.mod is measured against. It may be nil for a module the file does not
// name, in which case such a rule cannot be satisfied.
func (p *Policy) Check(module string, version, required *semver.Version) Decision {
	d := Decision{Module: module, Verdict: NotAllowed}

	r, _ := p.lookup(p.root, strings.Split(module, "/"), 0)
	if r == nil {
		return d
	}
	d.Pattern = r.pattern

	// A denial is checked first, so naming a module in both places refuses it
	// rather than leaving the outcome to the order the fields were read.
	if r.deny != nil {
		d.Constraint = r.deny.text
		if r.deny.allows(version, required) {
			d.Verdict = Denied
			return d
		}
	}
	if r.allow != nil {
		d.Constraint = r.allow.text
		if r.allow.allows(version, required) {
			d.Verdict = Allowed
			return d
		}
		// A rule matched the path but not the version, which is a different
		// problem from having no rule at all: the module needs moving, not
		// the policy.
		d.Verdict = VersionDenied
		return d
	}
	// A rule that only denies, and did not match, leaves the module
	// unpermitted rather than permitted.
	return d
}

// lookup walks the trie, returning the highest-scoring rule it reaches and the
// score that rule earned.
func (p *Policy) lookup(n *node, segments []string, score int) (*rule, int) {
	best, bestScore := (*rule)(nil), -1
	if n.rule != nil {
		best, bestScore = n.rule, score
	}
	if len(segments) == 0 || n.children == nil {
		return best, bestScore
	}

	// A trailing wildcard matches here and everything below it.
	if c := n.children[Rest]; c != nil && c.rule != nil && score+1 > bestScore {
		best, bestScore = c.rule, score+1
	}
	// A literal segment scores higher than a single-segment wildcard, so an
	// exact path wins wherever one exists.
	for _, key := range []string{segments[0], One} {
		c := n.children[key]
		if c == nil {
			continue
		}
		weight := 1
		if key == segments[0] {
			weight = 2
		}
		if r, s := p.lookup(c, segments[1:], score+weight); r != nil && s > bestScore {
			best, bestScore = r, s
		}
	}
	return best, bestScore
}
