package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The conditions a rule can respond to. Each names a different problem, and so
// a different fix.
const (
	// CondVulnReachable is an advisory covering code this project reaches.
	CondVulnReachable = "vuln-reachable"
	// CondVulnPresent is an advisory in a module the project depends on but
	// whose vulnerable code it does not reach.
	CondVulnPresent = "vuln-present"
	// CondNotAllowed is a module no rule covers, which needs a rule.
	CondNotAllowed = "not-allowed"
	// CondDenied is a module a rule refuses, which needs that rule
	// reconsidered.
	CondDenied = "denied"
	// CondVersionDenied is a module whose version failed its constraint,
	// which needs the module moved rather than the policy changed.
	CondVersionDenied = "version-denied"
)

// Conditions lists the conditions a policy may respond to, for help text and
// error messages.
func Conditions() []string {
	return []string{
		CondVulnReachable, CondVulnPresent,
		CondNotAllowed, CondDenied, CondVersionDenied,
	}
}

// file mirrors the on-disk form of a policy.
type file struct {
	// Actions names what each outcome does, so that what "fail" means is
	// stated once rather than repeated at every rule.
	Actions map[string]struct {
		Exit *int   `json:"exit"`
		Log  string `json:"log"`
	} `json:"actions"`
	// Modules maps a path pattern to the actions permitted for it, keyed by
	// action so that several can apply to one pattern.
	Modules map[string]map[string]string `json:"modules"`
	// Rules pair a condition with the action to take when it is met.
	Rules []struct {
		When string `json:"when"`
		Then string `json:"then"`
	} `json:"rules"`
}

// Load reads and merges policy files, in order.
//
// Later files override earlier ones for the same pattern, action or condition,
// which is what lets a security-managed baseline be distributed and a project
// add to it. Anything mutually exclusive belongs in a separate run rather than
// in a rule that has to be reconciled here.
func Load(paths []string) (*Policy, error) {
	p := New()
	for _, path := range paths {
		if err := p.load(path); err != nil {
			return nil, err
		}
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// load merges one file into the policy.
func (p *Policy) load(path string) (err error) {
	// The file is read through a root confined to its directory, so a path
	// naming a symlink cannot reach outside it.
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("policy %q: %w", path, err)
	}
	body, err := root.ReadFile(name)
	if closeErr := root.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("policy %q: %w", path, err)
	}

	var f file
	dec := json.NewDecoder(strings.NewReader(string(body)))
	// An unknown key is more likely a typo than an extension, and silently
	// ignoring one in a security policy would hide the mistake.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("policy %q: %w", path, err)
	}

	for name, a := range f.Actions {
		exit := 1
		if a.Exit != nil {
			exit = *a.Exit
		}
		p.actions[name] = Action{Name: name, Exit: exit, Log: a.Log}
	}
	for pattern, actions := range f.Modules {
		var allow, deny string
		for action, constraint := range actions {
			switch action {
			case "allow":
				allow = constraint
			case "deny":
				deny = constraint
			default:
				return fmt.Errorf("policy %q: pattern %q: unknown action %q, expected allow or deny",
					path, pattern, action)
			}
		}
		if err := p.Add(pattern, allow, deny); err != nil {
			return fmt.Errorf("policy %q: %w", path, err)
		}
	}
	for _, r := range f.Rules {
		if !slices.Contains(Conditions(), r.When) {
			return fmt.Errorf("policy %q: unknown condition %q, expected one of: %s",
				path, r.When, strings.Join(Conditions(), ", "))
		}
		p.conditions[r.When] = r.Then
	}
	return nil
}

// validate reports a policy that cannot be applied as written.
func (p *Policy) validate() error {
	for condition, action := range p.conditions {
		if _, ok := p.actions[action]; !ok {
			return fmt.Errorf("condition %q names action %q, which no policy defines; defined: %s",
				condition, action, strings.Join(slices.Sorted(maps.Keys(p.actions)), ", "))
		}
	}
	return nil
}

// Action returns what to do about a condition, and whether the policy has an
// opinion on it at all.
func (p *Policy) Action(condition string) (Action, bool) {
	name, ok := p.conditions[condition]
	if !ok {
		return Action{}, false
	}
	return p.actions[name], true
}

// ScansVulnerabilities reports whether any rule needs a vulnerability scan, so
// that a policy asking about advisories does not depend on the caller also
// remembering to ask for them.
func (p *Policy) ScansVulnerabilities() bool {
	for _, condition := range []string{CondVulnReachable, CondVulnPresent} {
		if _, ok := p.conditions[condition]; ok {
			return true
		}
	}
	return false
}
