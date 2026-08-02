package app

import (
	"strings"
	"testing"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// TestPeriodsResolve checks where the two periods come from when a flag, an
// environment variable and a policy all have something to say.
//
// The caller on the command line is the most specific voice and wins. A policy is
// the next, since someone wrote it down deliberately. The built-in default is only
// the answer when nobody said anything -- and because the flag carries that default,
// "did the caller say" has to be asked of the command rather than inferred from the
// value, which is why CooldownSet exists.
func TestPeriodsResolve(t *testing.T) {
	day := 24 * time.Hour

	for _, tc := range []struct {
		name        string
		flag        string
		set         bool
		policy      string
		wantCooling time.Duration
	}{{
		// Nobody said, so the built-in default stands.
		name:        "neither",
		flag:        DefaultCooldown,
		wantCooling: 7 * day,
	}, {
		// Only the policy said.
		name:        "policy only",
		flag:        DefaultCooldown,
		policy:      "14d",
		wantCooling: 14 * day,
	}, {
		// The caller said, so the policy yields.
		name:        "caller overrides the policy",
		flag:        "21d",
		set:         true,
		policy:      "14d",
		wantCooling: 21 * day,
	}, {
		// Explicitly asking for the same value as the default is still asking, and
		// must beat a policy saying otherwise.
		name:        "caller names the default",
		flag:        DefaultCooldown,
		set:         true,
		policy:      "90d",
		wantCooling: 7 * day,
	}, {
		// Zero is a value, not an absence: it disables the cooldown.
		name:        "caller disables it",
		flag:        "0",
		set:         true,
		policy:      "14d",
		wantCooling: 0,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppEnv{
				Cooldown:    tc.flag,
				CooldownSet: tc.set,
				Churn:       DefaultChurn,
			}
			var policy *time.Duration
			if tc.policy != "" {
				d := mustPeriod(t, tc.policy)
				policy = &d
			}
			got, _, err := app.periods(policy, nil)
			if err != nil {
				t.Fatalf("periods: %v", err)
			}
			if got != tc.wantCooling {
				t.Errorf("cooldown = %v, want %v", got, tc.wantCooling)
			}
		})
	}
}

// TestPeriodsRejectChurnBelowCooldown checks that a churn window shorter than the
// cooldown is refused rather than silently doing nothing.
//
// Churn is detected by finding an earlier release inside the window. A window
// narrower than the cooldown cannot contain one, since every release inside it is
// also inside the cooldown -- so the setting would never fire and a caller who
// asked for it would never learn why.
func TestPeriodsRejectChurnBelowCooldown(t *testing.T) {
	app := &AppEnv{Cooldown: "30d", CooldownSet: true, Churn: "7d", ChurnSet: true}
	if _, _, err := app.periods(nil, nil); err == nil {
		t.Fatal("periods succeeded, want an error")
	} else {
		for _, want := range []string{"churn", "cooldown", "7d", "30d"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	}
}

// TestPeriodsAllowChurnEqualToCooldown checks the boundary: a window exactly as long
// as the cooldown is accepted, since a release at the far edge of it is settled and
// so is a genuine earlier release.
func TestPeriodsAllowChurnEqualToCooldown(t *testing.T) {
	app := &AppEnv{Cooldown: "7d", Churn: "7d"}
	if _, _, err := app.periods(nil, nil); err != nil {
		t.Errorf("periods: %v", err)
	}
}

// TestPeriodsRejectBadValue checks that an unreadable period fails, naming which of
// the two it was so the caller knows which to fix.
func TestPeriodsRejectBadValue(t *testing.T) {
	for _, tc := range []struct{ name, cooldown, churn, want string }{
		{name: "cooldown", cooldown: "7x", churn: DefaultChurn, want: "cooldown"},
		{name: "churn", cooldown: DefaultCooldown, churn: "soon", want: "churn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppEnv{Cooldown: tc.cooldown, Churn: tc.churn}
			_, _, err := app.periods(nil, nil)
			if err == nil {
				t.Fatal("periods succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
		})
	}
}

// mustPeriod reads a period a test states as a literal, failing the test rather than
// returning an error the caller has to check.
func mustPeriod(t *testing.T, text string) time.Duration {
	t.Helper()
	d, err := module.ParseDuration(text)
	if err != nil {
		t.Fatalf("ParseDuration(%q): %v", text, err)
	}
	return d
}
