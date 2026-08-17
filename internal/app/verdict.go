package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// refusal is an upgrade that will not be applied, and why.
type refusal struct {
	// Upgrade is the module that was selected, which is the one to decline. It is not
	// always the module objected to: an upgrade can be refused for what it drags in,
	// and declining the module that suffered that would be declining something nobody
	// chose.
	Upgrade string
	// Reason states what is wrong with the version this upgrade would install.
	Reason string
	// Remedy names what would resolve it, since a refusal a reader cannot act on is
	// just an obstacle.
	Remedy string
	// Advisories holds the identifiers behind the reason, empty for a policy refusal.
	Advisories []string
}

// violation renders a refusal as something the policy report can carry.
//
// A withheld upgrade is a policy finding like any other -- the cooldown and the advisory
// guard are this tool's own policy, as much as any file is -- so it travels the same way
// and is reported in the same place rather than through a channel of its own.
func (r refusal) violation(action policy.Action) violation {
	return violation{
		Module:     r.Upgrade,
		Condition:  policy.CondUpgradeWithheld,
		Detail:     r.Reason,
		Remedy:     r.Remedy,
		Advisories: r.Advisories,
		Action:     action,
	}
}

// resolved works out where every module lands if the given upgrades are taken, and
// which selected upgrade dragged each module that moved.
//
// Go selects the highest version anything asks for, so taking one upgrade can move a
// module nobody chose: aws-sdk-go-v2 v1.43.3 requires smithy-go v1.27.6, and taking the
// first moves the second. A policy therefore has to be checked against the outcome, not
// against the available modules -- which is what let a forbidden version arrive through
// an upgrade to something else entirely.
//
// This is minimal version selection over one step. It does not recurse into what the
// new requirements themselves require, because the point is to catch what this run
// would do rather than to reimplement the module graph: anything deeper is reported by
// the next run, and reaching for it here would mean fetching the whole graph to answer
// a question about a handful of upgrades.
func resolved(build map[string]string, taking []candidate, asks map[string]requires) (at map[string]string, by map[string]string) {
	at = make(map[string]string, len(build))
	for path, version := range build {
		at[path] = version
	}
	by = map[string]string{}

	// The selected upgrades themselves, which are chosen rather than dragged.
	for _, c := range taking {
		at[c.Path] = c.Version
	}
	// Then what they require, taking the highest of anything asked for twice.
	for _, c := range taking {
		for path, want := range asks[c.Path] {
			asked, err := semver.NewVersion(want)
			if err != nil {
				// A version that will not parse says nothing about where the module
				// lands, so it is left where it was rather than guessed at.
				continue
			}
			if held, ok := at[path]; ok {
				has, err := semver.NewVersion(held)
				if err != nil || !has.LessThan(asked) {
					continue
				}
			}
			at[path], by[path] = want, c.Path
		}
	}
	return at, by
}

// deniedByOutcome returns the upgrades a policy will not permit, judged by where the
// build list would land rather than by what is available.
//
// Only the modules that would move are checked. One already sitting at a version the
// policy refuses is a problem this run did not cause, and enforce reports it; refusing
// an unrelated upgrade over it would leave a reader unable to make progress on
// anything.
func deniedByOutcome(rules *policy.Policy, build map[string]string, taking []candidate, asks map[string]requires) []refusal {
	if rules == nil || len(taking) == 0 {
		return nil
	}
	after, by := resolved(build, taking, asks)

	// Which selected upgrade to blame for each module that moved. A module that moved
	// on its own account answers for itself.
	blame := func(path string) string {
		if who, ok := by[path]; ok {
			return who
		}
		return path
	}

	var refused []refusal
	seen := map[string]struct{}{}
	for _, c := range taking {
		for path, lands := range after {
			if lands == build[path] {
				// Not moved by this run, so not this run's to answer for.
				continue
			}
			if blame(path) != c.Path {
				continue
			}
			v, err := semver.NewVersion(lands)
			if err != nil {
				continue
			}
			// The version installed is what a "go.mod" constraint defers to, so the
			// prospective version stands as both: it is about to be what go.mod says.
			d := rules.Check(path, v, v)
			if d.Verdict == policy.Allowed {
				continue
			}
			if _, ok := rules.Action(d.Verdict.String()); !ok {
				// The policy has no opinion on this outcome, so it is not a refusal.
				continue
			}
			if _, had := seen[c.Path]; had {
				continue
			}
			seen[c.Path] = struct{}{}

			reason := fmt.Sprintf("%s %s: %s", path, lands, detail(d, module.Module{Name: path, From: v}))
			if path != c.Path {
				reason = fmt.Sprintf("requires %s", reason)
			}
			refused = append(refused, refusal{
				Upgrade: c.Path,
				Reason:  reason,
				Remedy:  fmt.Sprintf("widen rule %q or leave this module at its current version", d.Pattern),
			})
		}
	}
	return refused
}

// vulnerableAfter returns the advisories a version would still be exposed to.
//
// An advisory covers every version below the one that fixes it, so a version below
// FixedIn lands on something the database already knows about. An advisory with no fix is
// not counted: nothing resolves it, so it is no reason to prefer one version over
// another, and refusing every upgrade over it would leave a module permanently stuck.
func vulnerableAfter(to string, vulns []vulnerability) []vulnerability {
	at, err := semver.NewVersion(to)
	if err != nil {
		return nil
	}
	var exposed []vulnerability
	for _, v := range vulns {
		if v.FixedIn == "" {
			continue
		}
		fixed, err := semver.NewVersion(strings.TrimPrefix(v.FixedIn, toolchainPrefix))
		if err != nil {
			// A fix version that cannot be read says nothing about where it sits.
			continue
		}
		if at.LessThan(fixed) {
			exposed = append(exposed, v)
		}
	}
	return exposed
}

// exposedByOutcome returns the upgrades that would land a module on a version an advisory
// still covers.
//
// The same shape as deniedByOutcome, and for the same reason: what matters is where the
// build list ends up rather than what was selected. An upgrade that drags a dependency
// onto a vulnerable release is precisely the case a per-module check cannot see.
//
// Only the modules that would move are judged. One already sitting on a vulnerable
// version is a problem this run did not cause, and refusing unrelated upgrades over it
// would block the very upgrade that fixes it.
func exposedByOutcome(build map[string]string, taking []candidate, asks map[string]requires, vulns vulnerabilities) []refusal {
	if len(taking) == 0 || len(vulns) == 0 {
		return nil
	}
	after, by := resolved(build, taking, asks)

	var refused []refusal
	seen := map[string]struct{}{}
	for _, c := range taking {
		for path, lands := range after {
			if lands == build[path] {
				continue
			}
			// Whichever selected upgrade moved it answers for where it landed.
			who, ok := by[path]
			if !ok {
				who = path
			}
			if who != c.Path {
				continue
			}
			exposed := vulnerableAfter(lands, vulns[path])
			if len(exposed) == 0 {
				continue
			}
			if _, had := seen[c.Path]; had {
				continue
			}
			seen[c.Path] = struct{}{}

			names := make([]string, 0, len(exposed))
			fix := strings.TrimPrefix(exposed[0].FixedIn, toolchainPrefix)
			for _, v := range exposed {
				names = append(names, v.CVE())
			}
			reason := fmt.Sprintf("%s %s is affected by %s", path, lands, strings.Join(names, ", "))
			if path != c.Path {
				reason = fmt.Sprintf("requires %s", reason)
			}
			refused = append(refused, refusal{
				Upgrade:    c.Path,
				Reason:     reason,
				Remedy:     fmt.Sprintf("upgrade %s to %s or later", path, fix),
				Advisories: names,
			})
		}
	}
	return refused
}

// withheld drops the upgrades that were refused, keeping the rest, and returns them as
// violations for the policy report.
//
// One refused upgrade must not cost a reader the rest of their selection, so the two
// results are independent: the modules still to apply, and the findings for the ones that
// are not. Reported as violations rather than as their own error type because withholding
// an upgrade is a policy decision, and a caller should not need two mechanisms to learn
// what the policy did.
func withheld(modules []module.Module, refused []refusal, action policy.Action) ([]module.Module, []violation) {
	if len(refused) == 0 {
		return modules, nil
	}
	drop := make(map[string]refusal, len(refused))
	for _, r := range refused {
		drop[r.Upgrade] = r
	}
	kept := make([]module.Module, 0, len(modules))
	var found []violation
	for _, mod := range modules {
		if r, ok := drop[mod.Name]; ok {
			found = append(found, r.violation(action))
			continue
		}
		kept = append(kept, mod)
	}
	return kept, found
}

// readCandidateRequires reads what each candidate requires.
//
// A variable rather than the function directly, so a test can answer as a failed
// lookup does. What permitted decides when the answer cannot be had is a rule about
// refusals, and reaching it otherwise needs a broken module cache.
var readCandidateRequires = candidateRequires

// permitted returns the upgrades a policy allows, having asked the toolchain what each
// would resolve to.
//
// Checked before anything is applied, because an upgrade that lands a forbidden version
// cannot be undone by reporting it afterwards -- and reporting it afterwards is what
// made a clean run install a version the next run then failed on.
func (app *AppEnv) permitted(ctx context.Context, dir string, modules []module.Module, rules *policy.Policy, vulns vulnerabilities) ([]module.Module, []violation) {
	if len(modules) == 0 || (rules == nil && len(vulns) == 0) {
		return modules, nil
	}
	// What the policy asked to happen when an upgrade is withheld. Withholding is this
	// tool's own decision, so it stands whether or not a file named the condition --
	// but a file that did name it decides the severity.
	action := policy.Action{Name: policy.CondUpgradeWithheld, Exit: 1}
	if rules != nil {
		if named, ok := rules.Action(policy.CondUpgradeWithheld); ok {
			action = named
		}
	}
	build, taking := installedForOutcome(modules)
	// What each target requires, read from the go.mod the module cache already holds.
	asks, err := readCandidateRequires(ctx, dir, taking)
	if err != nil {
		// Without the requirements the outcome cannot be predicted. Refusing every
		// upgrade over a failed lookup would be worse than proceeding, since enforce
		// still reports whatever lands, so this is reported and allowed through.
		log.Trace().Err(err).Msg("Could not read what the upgrades would require")
		return modules, nil
	}
	// Both gates ask the same question of the same outcome -- whether the build list
	// would land somewhere it should not -- so they share the resolution and are
	// reported together.
	refused := deniedByOutcome(rules, build, taking, asks)
	refused = append(refused, exposedByOutcome(build, taking, asks, vulns)...)
	return withheld(modules, refused, action)
}

// installedForOutcome describes the state a refusal check reasons from: what the
// build list holds now, and which upgrades are being taken.
//
// One entry per module path, however many rows name it. A workspace splits a module
// into a row per requirement, and both maps are keyed by path: the build list holds
// one version per module because a build does, and each candidate costs a go list
// subprocess, so asking twice about one target buys nothing.
//
// The highest requirement stands for the module. Go resolves a requirement shared by
// several members to the highest of them, so that is the version the build would
// select and the one a policy has to be judged against. Taking whichever row arrived
// last would answer differently under a different --sort, since the rows reach this
// point in sorted order.
func installedForOutcome(modules []module.Module) (map[string]string, []candidate) {
	build := map[string]string{}
	taking := make([]candidate, 0, len(modules))
	for _, mod := range modules {
		at := "v" + mod.From.String()
		held, seen := build[mod.Name]
		if !seen {
			taking = append(taking, candidate{Path: mod.Name, Version: mod.To.Original()})
			build[mod.Name] = at
			continue
		}
		// Already named by an earlier row, so keep the higher of the two versions.
		if was, err := semver.NewVersion(held); err == nil && was.LessThan(mod.From) {
			build[mod.Name] = at
		}
	}
	return build, taking
}
