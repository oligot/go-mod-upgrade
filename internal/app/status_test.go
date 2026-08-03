package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// TestPolicyErrorCarriesTheViolations checks that the error reports what the policy
// objected to, and does not decide what to do about it.
//
// An exit code is the caller's decision, not a fact about the failure. Injecting one at
// construction means every future caller inherits a choice made here -- and a library
// that reports "policy violations, exit 42" cannot be used by anything that wanted to
// count them instead.
func TestPolicyErrorCarriesTheViolations(t *testing.T) {
	fail := policy.Action{Name: "fail", Exit: 1}
	halt := policy.Action{Name: "halt", Exit: 42}

	err := &PolicyError{Violations: []violation{
		{Module: "example.com/a", Condition: policy.CondDenied, Action: fail},
		{Module: "example.com/b", Condition: policy.CondNotAllowed, Action: halt},
	}}

	// Recoverable from a join, which is how a run reports several things at once.
	var got *PolicyError
	if !errors.As(errors.Join(errors.New("other"), err), &got) {
		t.Fatal("errors.As found no PolicyError")
	}
	if len(got.Violations) != 2 {
		t.Errorf("got %d violations, want 2", len(got.Violations))
	}
	// Every violation appears in the message. An error saying only "2 violations"
	// forces a reader back to the report to learn which, and anything capturing the
	// error rather than the terminal would have lost them.
	for _, want := range []string{"example.com/a", "denied", "example.com/b", "not-allowed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Error() = %q, does not mention %q", err.Error(), want)
		}
	}
}

// TestExitStatusDerivesFromWhatFailed checks that the code a run leaves with is worked
// out from the violations, at the point of deciding, rather than read from a field.
//
// The highest status any failing action asked for wins, so a warning alongside a failure
// still fails and a policy asking for 42 gets 42.
func TestExitStatusDerivesFromWhatFailed(t *testing.T) {
	fail := policy.Action{Name: "fail", Exit: 1}
	halt := policy.Action{Name: "halt", Exit: 42}
	warn := policy.Action{Name: "warn", Exit: 0}

	for _, tc := range []struct {
		name string
		err  error
		want int
	}{{
		// Nothing wrong at all.
		name: "no error",
		err:  nil,
		want: 0,
	}, {
		name: "an ordinary failure",
		err:  errors.New("something broke"),
		want: 1,
	}, {
		name: "one violation",
		err:  &PolicyError{Violations: []violation{{Action: fail}}},
		want: 1,
	}, {
		// The policy chose the code, so the policy gets it.
		name: "the policy asked for a specific status",
		err:  &PolicyError{Violations: []violation{{Action: halt}}},
		want: 42,
	}, {
		name: "the highest failing status wins",
		err:  &PolicyError{Violations: []violation{{Action: fail}, {Action: halt}}},
		want: 42,
	}, {
		// A warning is not a failure, so it does not choose a code -- but reaching
		// ExitStatus at all means something else went wrong, so it is not success.
		name: "warnings alone",
		err:  &PolicyError{Violations: []violation{{Action: warn}}},
		want: 1,
	}, {
		// Wrapped, as a run's joined error would carry it.
		name: "wrapped in a join",
		err:  errors.Join(errors.New("other"), &PolicyError{Violations: []violation{{Action: halt}}}),
		want: 42,
	}, {
		// A withheld upgrade travels as a violation like anything else the policy
		// decided, so it chooses a code the same way.
		name: "a withheld upgrade",
		err: &PolicyError{Violations: []violation{{
			Module:    "example.com/m",
			Condition: policy.CondUpgradeWithheld,
			Detail:    "affected by CVE-2026-0001",
			Action:    halt,
		}}},
		want: 42,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (&AppEnv{}).ExitStatus(tc.err); got != tc.want {
				t.Errorf("ExitStatus() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestWithheldUpgradeIsAPolicyFinding checks that a withheld upgrade is reported the same
// way as anything else the policy decided.
//
// The cooldown and the advisory guard are this tool's own policy, as much as a file is, so
// withholding an upgrade needs no separate channel -- a caller learning what the policy did
// should not have to check two mechanisms to find out.
func TestWithheldUpgradeIsAPolicyFinding(t *testing.T) {
	err := &PolicyError{Violations: []violation{{
		Module:     "example.com/app",
		Condition:  policy.CondUpgradeWithheld,
		Detail:     "requires example.com/lib v1.2.0, affected by CVE-2026-0001",
		Remedy:     "upgrade example.com/lib to v1.5.0 or later",
		Advisories: []string{"CVE-2026-0001"},
		Action:     policy.Action{Name: "fail", Exit: 1},
	}}}

	var got *PolicyError
	if !errors.As(err, &got) {
		t.Fatal("errors.As found no PolicyError")
	}
	// Both the fact and what to do about it survive into the message.
	for _, want := range []string{"example.com/app", "CVE-2026-0001", "v1.5.0 or later"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Error() = %q, does not mention %q", err.Error(), want)
		}
	}
	// And the identifiers are available without parsing prose.
	if len(got.Violations[0].Advisories) != 1 {
		t.Errorf("Advisories = %v, want the identifiers", got.Violations[0].Advisories)
	}
}
