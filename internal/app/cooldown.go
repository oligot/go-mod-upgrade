package app

import (
	"fmt"
	"time"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// periods resolves how long a release must settle and over what window repeated
// releasing counts, given what a policy asked for.
//
// The caller on the command line wins, then the policy, then the built-in default.
// A policy is consulted only when the caller said nothing, which is why the Set
// fields exist: the flag carries the default, so the value alone cannot say whether
// anyone chose it.
func (app *AppEnv) periods(policyCooldown, policyChurn *time.Duration) (cooldown, churn time.Duration, err error) {
	// wrote keeps the text each period was given as, so a complaint about the pair
	// quotes what someone actually typed rather than a normalised form: a caller who
	// wrote "7d" should not have to recognise it as "1w" to find the setting.
	var wrote [2]string
	for i, p := range []struct {
		name   string
		text   string
		named  bool
		policy *time.Duration
		into   *time.Duration
	}{
		{name: "cooldown", text: app.Cooldown, named: app.CooldownSet, policy: policyCooldown, into: &cooldown},
		{name: "churn", text: app.Churn, named: app.ChurnSet, policy: policyChurn, into: &churn},
	} {
		if !p.named && p.policy != nil {
			*p.into = *p.policy
			// The policy gave a duration rather than the text behind it, so render
			// it back.
			wrote[i] = module.FormatDuration(*p.policy)
			continue
		}
		d, parseErr := module.ParseDuration(p.text)
		if parseErr != nil {
			return 0, 0, fmt.Errorf("%s: %w", p.name, parseErr)
		}
		*p.into, wrote[i] = d, p.text
	}

	// Churn is detected by finding a release earlier than the newest but still
	// inside the window. A window narrower than the cooldown cannot hold one --
	// every release inside it is also too fresh to recommend -- so the setting would
	// never fire, and a caller who asked for it would never learn why.
	if churn > 0 && cooldown > 0 && churn < cooldown {
		return 0, 0, fmt.Errorf("churn %s is shorter than cooldown %s, so no release could ever count as churn; widen churn to at least the cooldown",
			wrote[1], wrote[0])
	}
	return cooldown, churn, nil
}
