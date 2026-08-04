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
	// CondGoOutsideBand is a project declaring a Go version outside the band its policy
	// supports, at either edge.
	//
	// One condition rather than two because a band has two edges and one meaning. Too new
	// drops consumers the project promised to support, since the go directive is a demand
	// on whoever builds the module; too old is outside the supported set, or carries an
	// advisory the band excludes. Either way the fix is the same directive.
	CondGoOutsideBand = "go-outside-band"
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
		CondGoOutsideBand, CondUpgradeWithheld,
	}
}

// file mirrors the on-disk form of a policy.
type file struct {
	// Include names further policy files to merge before this one, in the same form
	// --policy takes. It exists so a baseline can be distributed with what it depends
	// on, rather than every caller having to name the same set in the right order.
	//
	// Paths are relative to the directory of the first file named, so one reads the
	// same wherever in the tree it appears.
	Include []string `json:"include"`
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
	// Go states the release channel the project keeps.
	//
	// SupportLookback is how many releases back consumers may be, which bounds the go
	// directive from ABOVE: promising to support the last two means declaring the older
	// of them, since "go 1.26" refuses to build for anyone on 1.25. A count rather than
	// a version because the answer moves when Go releases.
	//
	// Requires is the opposite promise, a floor: the oldest toolchain this project will
	// work with, named outright. An application controlling its own toolchain wants
	// this; a library shipping to others wants the lookback. Both may be set.
	Go *struct {
		SupportedMinor  *string `json:"supported-minor"`
		SupportedPatch  *string `json:"supported-patch"`
		ExcludeCVE      *bool   `json:"exclude-cve"`
		AllowPrerelease *bool   `json:"allow-prerelease"`
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
	if len(paths) == 0 {
		// Nothing to read, so nothing permits anything. validate says so.
		return nil, p.validate()
	}
	// Everything a file includes is read through a root confined to the directory of
	// the first file named, so an include cannot reach outside the set the caller
	// pointed at and reads the same wherever the run started from.
	dir := filepath.Dir(paths[0])
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", paths[0], err)
	}
	defer func() { _ = root.Close() }()

	// Which files have been merged, keyed by where they sit rather than by how they
	// were named, so a baseline two overlays both include is read once and a cycle
	// between them terminates. The caller's own files are recorded too: naming a
	// baseline on the command line and including it from an overlay asks for it once.
	seen := map[string]struct{}{}
	for _, path := range paths {
		body, err := readPolicy(path)
		if err != nil {
			return nil, err
		}
		seen[resolve(path)] = struct{}{}
		if err := p.load(root, dir, path, body, seen); err != nil {
			return nil, err
		}
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// resolve returns the key a file is remembered by: where it sits, rather than how it
// was named.
//
// Absolute, so that a path relative to the working directory and one relative to the
// root agree when they name the same file. Symlinks are followed too, since a link is
// another name for a file rather than another file: a policy including one would
// otherwise be parsed once per name it is reachable by.
//
// A link that cannot be followed falls back to the textual path. That is the honest
// answer -- the file is about to be opened, and failing here would refuse a policy over
// a link the run had no need to resolve -- and it costs at worst the repeated parse this
// exists to avoid, since the absolute path still terminates a cycle.
func resolve(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

// readPolicy reads a file the caller named, which may sit anywhere.
func readPolicy(path string) (body []byte, err error) {
	// The file is read through a root confined to its directory, so a path
	// naming a symlink cannot reach outside it.
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", path, err)
	}
	body, err = root.ReadFile(name)
	if closeErr := root.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", path, err)
	}
	return body, nil
}

// load merges one file into the policy, having merged whatever it includes.
//
// root confines every include to dir, the directory of the first file the caller
// named, and dir itself is carried so an included path can be reported and
// remembered as the place it resolves to.
func (p *Policy) load(root *os.Root, dir, path string, body []byte, seen map[string]struct{}) error {
	var f file
	dec := json.NewDecoder(strings.NewReader(string(body)))
	// An unknown key is more likely a typo than an extension, and silently
	// ignoring one in a security policy would hide the mistake.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("policy %q: %w", path, err)
	}

	// Included files are merged first, so a file including a baseline overrides it --
	// the same order --policy gives, with the including file last.
	for _, include := range f.Include {
		if filepath.IsAbs(include) {
			return fmt.Errorf("policy %q: include %q must be relative to %q",
				path, include, dir)
		}
		name := filepath.Clean(include)
		at := resolve(filepath.Join(dir, name))
		if _, had := seen[at]; had {
			continue
		}
		seen[at] = struct{}{}
		included, err := root.ReadFile(name)
		if err != nil {
			return fmt.Errorf("policy %q: include %q: %w", path, include, err)
		}
		if err := p.load(root, dir, at, included, seen); err != nil {
			return err
		}
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
	if f.Go != nil {
		// Each bound is set on its own, so a file naming one leaves the others to
		// whatever else is stacked -- the same per-field merge the rest of a policy uses.
		for _, b := range []struct {
			name string
			from *string
			into *[]Relative
		}{
			{"supported-minor", f.Go.SupportedMinor, &p.band.Minor},
			{"supported-patch", f.Go.SupportedPatch, &p.band.Patch},
		} {
			if b.from == nil {
				continue
			}
			// Read here so a bound that will not parse fails while the file is being
			// read rather than after the network work.
			bounds, err := ParseBounds(*b.from)
			if err != nil {
				return fmt.Errorf("policy %q: go %s: %w", path, b.name, err)
			}
			*b.into = bounds
		}
		if f.Go.ExcludeCVE != nil {
			p.band.ExcludeCVE = *f.Go.ExcludeCVE
		}
		if f.Go.AllowPrerelease != nil {
			p.band.AllowPrerelease = *f.Go.AllowPrerelease
		}
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
			case "cooldown":
				// Read here, as the run-wide periods are, so a value that will not parse
				// fails while the file is being read rather than after the network work
				// -- and so it is never mistaken for no period at all, which would read
				// as a working rule that withholds nothing.
				d, err := module.ParseDuration(value)
				if err != nil {
					return fmt.Errorf("policy %q: pattern %q: cooldown: %w", path, pattern, err)
				}
				m.Cooldown = &d
			default:
				return fmt.Errorf("policy %q: pattern %q: unknown field %q, expected allow, deny, archived or cooldown",
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
