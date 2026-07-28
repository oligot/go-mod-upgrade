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
	// Detail says what to do about it.
	Detail string
	// Action is what the policy asked for.
	Action policy.Action
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

	d := p.Check(mod.Name, mod.From, mod.From)
	if d.Verdict == policy.Allowed {
		return found
	}
	action, ok := p.Action(d.Verdict.String())
	if !ok {
		// The policy has no opinion on this outcome, so it is not a violation.
		return found
	}
	found = append(found, violation{
		Module:    mod.Name,
		Condition: d.Verdict.String(),
		Detail:    detail(d),
		Action:    action,
	})
	return found
}

// detail says what to do about a verdict, since each calls for a different fix.
func detail(d policy.Decision) string {
	switch d.Verdict {
	case policy.NotAllowed:
		return "no rule covers this module"
	case policy.Denied:
		return fmt.Sprintf("refused by rule %q", d.Pattern)
	case policy.VersionDenied:
		return fmt.Sprintf("rule %q requires %s", d.Pattern, d.Constraint)
	default:
		return d.Verdict.String()
	}
}

// report writes the violations and returns the status to leave with.
//
// The highest status any action asked for wins, so a warning alongside a failure
// still fails.
func report(violations []violation) int {
	if len(violations) == 0 {
		return 0
	}

	// A spinner may have left the cursor mid-line, so start on a fresh one:
	// each violation has to begin at column zero to be worth grepping for.
	if _, err := fmt.Fprintln(color.Error); err != nil {
		log.WithError(err).Debug("Error while starting the report")
	}

	failed, warned, status := 0, 0, 0
	for _, v := range violations {
		mark, paint := "!", color.New(color.FgYellow).SprintFunc()
		if v.Action.Fails() {
			mark, paint = "x", color.New(color.Bold, color.FgRed).SprintFunc()
			failed++
			if got := v.Action.Status(); got > status {
				status = got
			}
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
	return status
}
