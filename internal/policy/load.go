package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// The conditions a rule can respond to. Each names a different problem, and so
// a different fix.
const (
	// CondVulnReachable is an advisory covering code this project reaches.
	CondVulnReachable = "vuln-reachable"
	// CondVulnPresent is an advisory in a module the project depends on but
	// whose vulnerable code it does not reach.
	CondVulnPresent = "vuln-present"
	// CondDeprecated is a module its author has deprecated. It describes the
	// module rather than one version, so no upgrade resolves it.
	CondDeprecated = "deprecated"
	// CondRetracted is a version its author has withdrawn. Unlike a deprecation
	// this is per version, so upgrading usually resolves it.
	CondRetracted = "retracted"
	// CondArchived is a module a policy asserts is abandoned.
	//
	// Alone among these it is asserted rather than observed: a human writes it
	// down and the toolchain can neither confirm nor refute it. It exists because
	// an abandoned module often declares nothing at all -- walking away is not
	// something an author files a notice for.
	CondArchived = "archived"
	// CondNotAllowed is a module no rule covers, which needs a rule.
	CondNotAllowed = "not-allowed"
	// CondDenied is a module a rule refuses, which needs that rule
	// reconsidered.
	CondDenied = "denied"
	// CondVersionDenied is a module whose version failed its constraint,
	// which needs the module moved rather than the policy changed.
	CondVersionDenied = "version-denied"
	// CondLocalPolicyException is a module already installed at a version this
	// policy forbids.
	//
	// Distinct from CondVersionDenied, which is about a version being refused. Here
	// the version is already in the tree: someone upgraded past the policy and is
	// accountable for it, so the run moves forward rather than failing over something
	// that has already happened and cannot be undone by refusing it now.
	//
	// "local" because the tree is not necessarily what is wrong. A shop with a more
	// informed opinion, or a policy that used to be wider, leaves a local policy
	// trailing what the project actually decided -- so the condition says which of the
	// two to go and look at rather than asserting the tree is at fault.
	CondLocalPolicyException = "local-policy-exception"
	// CondGoUnsupported is a project declaring a Go version older than the policy
	// supports, which needs the toolchain moved rather than the policy changed.
	CondGoUnsupported = "go-unsupported"
	// CondUpgradeWithheld is an upgrade that was not applied because the version it
	// would have installed is one the policy refuses or an advisory covers.
	//
	// Unlike the conditions above it describes something prevented rather than
	// something found: the run declined to act, and says so. It covers both sources
	// because the built-in rules -- the cooldown, and not moving onto a known
	// vulnerable release -- are as much this tool's policy as any file is.
	CondUpgradeWithheld = "upgrade-withheld"
)

// Conditions lists the conditions a policy may respond to, for help text and
// error messages.
func Conditions() []string {
	return []string{
		CondVulnReachable, CondVulnPresent,
		CondDeprecated, CondRetracted, CondArchived,
		CondNotAllowed, CondDenied, CondVersionDenied, CondLocalPolicyException,
		CondGoUnsupported, CondUpgradeWithheld,
	}
}

// file mirrors the on-disk form of a policy.
type file struct {
	// Tags names the build configurations to analyse, in the same form --tags
	// takes. A policy that asks about advisories decides which configurations
	// they are looked for in, so a caller need only name the policy.
	Tags []string `json:"tags"`
	// Cooldown is how long a release must sit before it is recommended, and Churn
	// the window over which repeated releasing is detected, both in the form
	// --cooldown takes. How long to wait is a judgement about risk, which is the
	// thing a policy states once for everyone.
	//
	// Pointers so that a file saying nothing is distinguishable from one asking for
	// zero, which disables the cooldown outright.
	Cooldown *string `json:"cooldown"`
	Churn    *string `json:"churn"`
	// Go says how many Go releases the project supports, so a project that has
	// fallen behind is reported. A count rather than a version because the answer
	// moves when Go releases: "the last two" stays correct, "1.25" does not.
	Go *struct {
		Releases *int `json:"releases"`
	} `json:"go"`
	// Actions names what each outcome does, so that what "fail" means is
	// stated once rather than repeated at every rule.
	Actions map[string]struct {
		Exit *int   `json:"exit"`
		Log  string `json:"log"`
	} `json:"actions"`
	// Modules maps a path pattern to what the file says about it, keyed by
	// field so that several can apply to one pattern.
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

	// A configuration one file asks for is one the run should cover, so the lists
	// accumulate rather than the last file winning: a baseline naming the
	// integration build and an overlay naming another want both.
	for _, tag := range f.Tags {
		if !slices.Contains(p.tags, tag) {
			p.tags = append(p.tags, tag)
		}
	}

	// A period is a single value rather than a list, so the later file wins: two
	// policies naming one both mean it, and the overlay is the more specific. Read
	// here rather than at the point of use so a typo fails while the file is being
	// read, not after the network work -- and so it is never mistaken for no
	// cooldown at all, which reads as a working policy that withholds nothing.
	for _, period := range []struct {
		field string
		text  *string
		into  **time.Duration
	}{
		{field: "cooldown", text: f.Cooldown, into: &p.cooldown},
		{field: "churn", text: f.Churn, into: &p.churn},
	} {
		if period.text == nil {
			continue
		}
		d, err := module.ParseDuration(*period.text)
		if err != nil {
			return fmt.Errorf("policy %q: %s: %w", path, period.field, err)
		}
		*period.into = &d
	}

	// Last file wins, as with the periods: a count is a single value, and an overlay
	// naming one is the more specific statement.
	if f.Go != nil && f.Go.Releases != nil {
		if *f.Go.Releases < 1 {
			return fmt.Errorf("policy %q: go releases: %d is not a window; name how many releases to support",
				path, *f.Go.Releases)
		}
		n := *f.Go.Releases
		p.goReleases = &n
	}

	for name, a := range f.Actions {
		exit := 1
		if a.Exit != nil {
			exit = *a.Exit
		}
		p.actions[name] = Action{Name: name, Exit: exit, Log: a.Log}
	}
	for pattern, fields := range f.Modules {
		var m Mark
		for field, value := range fields {
			switch field {
			case "allow":
				m.Allow = value
			case "deny":
				m.Deny = value
			case "archived":
				// A bare "true" would name no reason, and an assertion the
				// toolchain cannot check is only reviewable if it says why.
				if value == "" {
					return fmt.Errorf("policy %q: pattern %q: archived needs a reason",
						path, pattern)
				}
				m.Archived = value
			default:
				return fmt.Errorf("policy %q: pattern %q: unknown field %q, expected allow, deny or archived",
					path, pattern, field)
			}
		}
		if err := p.Add(pattern, m); err != nil {
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
//
// The check is made after every file has been read, so a baseline carrying the
// rules lets an overlay name only the modules it adds.
func (p *Policy) validate() error {
	// A policy with no rules can only ever pass, whatever it says about
	// modules, so it is refused rather than left to fail open.
	if len(p.conditions) == 0 {
		return fmt.Errorf("no rules, so nothing can fail; name a condition from: %s",
			strings.Join(Conditions(), ", "))
	}
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
