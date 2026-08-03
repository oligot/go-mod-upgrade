package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/fatih/color"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// violation is one thing a policy objected to.
type violation struct {
	// Module is the path objected to.
	Module string
	// Condition names what was wrong, which is also the rule that fired.
	Condition string
	// Detail says what is wrong.
	Detail string
	// Remedy names what would resolve it, empty when the detail is the whole of the
	// advice. A finding a reader cannot act on is just an obstacle.
	Remedy string
	// Advisories holds the identifiers behind the detail, kept apart from the prose so
	// a caller can act on them without parsing a sentence.
	Advisories []string
	// Action is what the policy asked for.
	Action policy.Action
}

// String renders one violation on a single line, for an error message.
//
// The report prints these across two lines with colour, which reads better on a terminal
// and worse anywhere else. This form is for the places a violation has to survive as
// text: an error, a log field, a test.
func (v violation) String() string {
	if v.Remedy == "" {
		return fmt.Sprintf("%s %s: %s", v.Module, v.Condition, v.Detail)
	}
	return fmt.Sprintf("%s %s: %s; %s", v.Module, v.Condition, v.Detail, v.Remedy)
}

// annotateArchived copies the archived marks a policy asserts onto the modules,
// so a listing shows them alongside what the toolchain reported.
//
// The mark lives in the policy rather than in go.mod, so without this it would
// reach the violation report and nothing else. A reader looking at a listing
// should see the same facts the gate acted on.
func annotateArchived(p *policy.Policy, modules []module.Module) {
	for i := range modules {
		if reason, ok := p.Archived(modules[i].Name); ok {
			modules[i].Archived = reason
		}
	}
}

// enforce checks every module against the policy and reports what it objects
// to.
//
// Every violation is collected rather than stopping at the first, so a run
// shows all the work rather than one finding per attempt.
func enforce(p *policy.Policy, modules []module.Module) []violation {
	var found []violation
	for _, mod := range modules {
		found = append(found, check(p, mod)...)
	}
	// Report the modules in the order they were listed, most severe first
	// within each, so the failures lead.
	slices.SortStableFunc(found, func(a, b violation) int {
		if a.Action.Fails() != b.Action.Fails() {
			if a.Action.Fails() {
				return -1
			}
			return 1
		}
		return 0
	})
	return found
}

// check reports what a policy objects to in one module.
func check(p *policy.Policy, mod module.Module) []violation {
	var found []violation

	// The advisories are independent of whether the module is permitted: a
	// module can be allowed and still carry something worth acting on.
	if mod.Reachable > 0 {
		if action, ok := p.Action(policy.CondVulnReachable); ok {
			found = append(found, violation{
				Module:    mod.Name,
				Condition: policy.CondVulnReachable,
				Detail: fmt.Sprintf("%s, reached by this code",
					strings.Join(mod.Vulns, ", ")),
				Action: action,
			})
		}
	}
	if present := len(mod.Vulns) - mod.Reachable; present > 0 {
		if action, ok := p.Action(policy.CondVulnPresent); ok {
			found = append(found, violation{
				Module:    mod.Name,
				Condition: policy.CondVulnPresent,
				Detail: fmt.Sprintf("%s, present but not reached",
					strings.Join(mod.Vulns, ", ")),
				Action: action,
			})
		}
	}

	// The author's own signals, which say nothing about whether the module is
	// permitted: a module can be allowed and still have been disowned upstream.
	if mod.IsDeprecated() {
		if action, ok := p.Action(policy.CondDeprecated); ok {
			found = append(found, violation{
				Module:    mod.Name,
				Condition: policy.CondDeprecated,
				// No upgrade resolves a deprecation, so the message is the
				// whole of the advice: it usually names the successor.
				Detail: mod.Deprecated,
				Action: action,
			})
		}
	}
	if mod.IsRetracted() {
		if action, ok := p.Action(policy.CondRetracted); ok {
			found = append(found, violation{
				Module:    mod.Name,
				Condition: policy.CondRetracted,
				Detail: fmt.Sprintf("%s withdrawn: %s", mod.From,
					strings.Join(mod.Retracted, "; ")),
				Action: action,
			})
		}
	}
	// An assertion rather than an observation, so the reason a reviewer gave is
	// what gets reported.
	if reason, ok := p.Archived(mod.Name); ok {
		if action, ok := p.Action(policy.CondArchived); ok {
			found = append(found, violation{
				Module:    mod.Name,
				Condition: policy.CondArchived,
				Detail:    reason,
				Action:    action,
			})
		}
	}

	// The version installed is what decides whether the tree is in breach. The
	// version merely on offer is not: permitted withholds an upgrade that would land a
	// forbidden version before it is applied, so an offer is a thing already prevented
	// rather than a thing to fail over.
	//
	// The version stands as both the version and the requirement, since a "go.mod"
	// constraint defers to what go.mod records and this is what it records.
	d := p.Check(mod.Name, mod.From, mod.From)
	if d.Verdict == policy.Allowed {
		return found
	}

	// A version the tree already holds is an exception rather than a denial: someone
	// upgraded past the policy and is accountable, and failing now neither undoes that
	// nor offers anyone something to act on today. It is also not certain the tree is
	// the thing that is wrong -- a wider policy elsewhere, or an earlier one here, may
	// be what the project actually decided against.
	//
	// Only a version constraint is softened this way. A module no rule covers, or one
	// a rule denies by path, is a different problem: no upgrade put it there, so there
	// is nobody to hold accountable and nothing to move forward from.
	condition := d.Verdict.String()
	if d.Verdict == policy.VersionDenied {
		condition = policy.CondLocalPolicyException
	}
	action, ok := p.Action(condition)
	if !ok {
		// The policy has no opinion on this outcome, so it is not a violation.
		return found
	}
	found = append(found, violation{
		Module:    mod.Name,
		Condition: condition,
		Detail:    detail(d, mod),
		Action:    action,
	})
	return found
}

// detail says what to do about a verdict, since each calls for a different fix.
func detail(d policy.Decision, mod module.Module) string {
	switch d.Verdict {
	case policy.NotAllowed:
		return "no rule covers this module"
	case policy.Denied:
		return fmt.Sprintf("refused by rule %q", d.Pattern)
	case policy.VersionDenied:
		// What the policy permits leads: a reader meeting this line does not yet know
		// what the rule is, and the exception only means something once they do.
		//
		// The cooldown is deliberately not mentioned. A constraint compares version
		// numbers, so waiting does not move it -- 1.27.6 never satisfies "<= 1.27.4"
		// however long anyone waits, and offering a period would promise something the
		// next run breaks.
		return fmt.Sprintf("policy %q permits %s; %s is installed",
			d.Pattern, d.Constraint, mod.From)
	default:
		return d.Verdict.String()
	}
}

// report writes the violations and reports whether any of them fails the run.
//
// Whether it fails is the fact; which status to leave with is the caller's decision, and
// depends on more than the violations -- so that is worked out where it is needed.
func report(violations []violation) bool {
	if len(violations) == 0 {
		return false
	}

	// A spinner may have left the cursor mid-line, so start on a fresh one:
	// each violation has to begin at column zero to be worth grepping for.
	if _, err := fmt.Fprintln(color.Error); err != nil {
		log.WithError(err).Debug("Error while starting the report")
	}

	failed, warned := 0, 0
	for _, v := range violations {
		mark, paint := "!", color.New(color.FgYellow).SprintFunc()
		if v.Action.Fails() {
			mark, paint = "x", color.New(color.Bold, color.FgRed).SprintFunc()
			failed++
		} else {
			warned++
		}
		_, err := fmt.Fprintf(color.Error, "%s %s  %s\n    %s\n",
			paint(mark), v.Module, paint(v.Condition), v.Detail)
		if err != nil {
			log.WithError(err).Error("Error while reporting a violation")
		}
	}

	log.WithFields(log.Fields{
		"failures": failed,
		"warnings": warned,
	}).Info("Policy checked")
	return failed > 0
}
