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
	"strings"

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
	// pattern is kept for reporting which rule decided a module.
	pattern string
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
	return c.versions.Check(version)
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
}

// Action is what happens when a condition is met.
type Action struct {
	// Name is the key the policy gave this action.
	Name string
	// Exit is the status to leave with. A POSIX status is a byte, so a value
	// outside 0-255 is reported as it will actually be observed.
	Exit int
	// Log names the level to report at, one of "error", "warn" or "info".
	Log string
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

// Add anchors a rule at a pattern. Later calls for the same pattern replace
// earlier ones, so merging several files is a matter of adding them in order.
func (p *Policy) Add(pattern string, allow, deny string) error {
	r := &rule{pattern: pattern}
	if allow != "" {
		c, err := parseConstraint(allow)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
		r.allow = c
	}
	if deny != "" {
		c, err := parseConstraint(deny)
		if err != nil {
			return fmt.Errorf("pattern %q: %w", pattern, err)
		}
		r.deny = c
	}

	cur := p.root
	for _, seg := range strings.Split(pattern, "/") {
		if cur.children == nil {
			cur.children = map[string]*node{}
		}
		if cur.children[seg] == nil {
			cur.children[seg] = &node{}
		}
		cur = cur.children[seg]
	}
	cur.rule = r
	return nil
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
