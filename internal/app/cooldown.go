package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"

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

// release is one published version of a module, with when it was published.
type release struct {
	Version string
	Time    time.Time
}

// stepLimit caps how far back a walk looks for a settled release.
//
// A module that has not had a settled release in twenty versions is churning far
// harder than this feature is meant to accommodate, and reporting that beats issuing a
// query for each of the 183 versions aws-sdk-go-v2 has published.
const stepLimit = 20

// parseVersions reads the versions a module has published from "go list -m
// -versions", newest first and capped at stepLimit.
//
// The output is one line: the module path followed by every version ever published,
// oldest first. It is reversed because a walk wants the newest candidates first, and
// capped for the reason stepLimit gives.
//
// A prerelease is not a candidate. Nobody waiting out a cooldown wants an untested
// release candidate offered instead, and Go publishes forms like
// "v2.0.0-preview.4+incompatible" that are prereleases in name and not upgrades at
// all.
func parseVersions(out []byte) []string {
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return nil
	}
	var versions []string
	// Skipping the path, and walking backwards so the newest come first.
	for i := len(fields) - 1; i >= 1 && len(versions) < stepLimit; i-- {
		v, err := semver.NewVersion(fields[i])
		if err != nil || v.Prerelease() != "" || v.Metadata() != "" {
			continue
		}
		versions = append(versions, fields[i])
	}
	return versions
}

// parseReleaseTimes reads when each version was published from "go list -m -json
// path@version ...", keyed by version.
//
// A version the toolchain gave no usable date for is left out rather than recorded as
// the zero time: zero reads as an ancient release, which would make an unknown version
// look like the settled one to step back to.
func parseReleaseTimes(out []byte) (map[string]time.Time, error) {
	times := map[string]time.Time{}
	// The objects are concatenated rather than wrapped in an array.
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var l listed
		if err := dec.Decode(&l); err != nil {
			return nil, fmt.Errorf("error parsing go list output: %w", err)
		}
		if l.Error != nil || l.Time == nil {
			continue
		}
		times[l.Version] = *l.Time
	}
	return times, nil
}

// step decides which version of a module to offer, given its release history
// newest-first, and reports whether the module is churning.
//
// A module whose newest release has settled is offered it, which is the ordinary
// case and costs nothing. The interesting case is a project that releases faster
// than the cooldown: aws-sdk-go-v2 publishes every one to three days, so its newest
// version is always too fresh and a rule that only waited would make it permanently
// ineligible. When that is happening -- the newest is still cooling and there is an
// earlier release inside the churn window -- the newest version that *has* settled is
// offered instead, so the module stays maintainable without recommending anything
// untested.
//
// A single fresh release with nothing else recent is deliberately not churn. One
// release is not a pattern, and stepping back for it would dig up an older version
// where waiting a few days is the honest answer. Such a module is offered nothing and
// simply waits.
//
// Offering nothing is a real answer, returned as the empty string: either the module
// is waiting, or it is churning so hard that no version in the history has settled.
func step(history []release, cooldown, churn time.Duration, at time.Time) (offer string, churning bool) {
	if len(history) == 0 {
		return "", false
	}
	settled := func(r release) bool { return at.Sub(r.Time) >= cooldown }

	// The newest release is what would ordinarily be offered, and if it has settled
	// there is nothing further to decide.
	if settled(history[0]) {
		return history[0].Version, false
	}

	// Churn is one release still cooling and another, earlier, inside the window.
	// The window is measured from now rather than from the newest release, since it
	// asks how recently this module has been active.
	if churn > 0 {
		for _, r := range history[1:] {
			if at.Sub(r.Time) <= churn {
				churning = true
				break
			}
		}
	}
	if !churning {
		return "", false
	}

	// Walk back to the newest release that has settled. The history is newest-first,
	// so the first one found is it.
	for _, r := range history[1:] {
		if settled(r) {
			return r.Version, true
		}
	}
	// Every version on offer is too fresh. Nothing can be recommended, and saying so
	// is better than reaching further back than the caller asked for.
	return "", true
}

// history reads when each of a module's recent versions was published, newest first.
//
// Two calls: one for the version list, then one batched call for their dates. Only
// reached for a module whose newest release is still cooling, so a project that
// releases at an ordinary pace never pays for it.
func history(ctx context.Context, dir, path string, cooldown time.Duration) ([]release, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-e", "-versions", path)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing versions of %s: %w", path, err)
	}
	versions := parseVersions(out)
	if len(versions) == 0 {
		return nil, nil
	}

	args := []string{"list", "-m", "-e", "-json"}
	for _, v := range versions {
		args = append(args, path+"@"+v)
	}
	cmd = exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err = cmd.Output(); err != nil {
		return nil, fmt.Errorf("dating versions of %s: %w", path, err)
	}
	times, err := parseReleaseTimes(out)
	if err != nil {
		return nil, err
	}

	// In the order the versions were asked for, which is newest first. A version
	// with no date is dropped rather than dated zero, since zero reads as ancient
	// and would be mistaken for the settled release to step back to.
	var found []release
	for _, v := range versions {
		if at, ok := times[v]; ok {
			found = append(found, release{Version: v, Time: at})
		}
	}
	return found, nil
}

// settle offers a churning module its newest settled version in place of a release
// that is still cooling.
//
// Only the modules whose newest release is too fresh are looked up, and only when a
// churn window was asked for. What a walk could not resolve is logged rather than
// passed over, since a module quietly left cooling looks the same as one the tool
// decided about.
func (app *AppEnv) settle(ctx context.Context, dir string, modules []module.Module) error {
	if app.churn <= 0 {
		return nil
	}
	var cooling []int
	for i := range modules {
		if modules[i].Cooling() {
			cooling = append(cooling, i)
		}
	}
	if len(cooling) == 0 {
		return nil
	}

	stop, err := progress(fmt.Sprintf("Checking release history (%d)", len(cooling)))
	if err != nil {
		return err
	}
	defer stop()

	cooldown := module.Cooldown()
	for _, i := range cooling {
		mod := &modules[i]
		found, err := history(ctx, dir, mod.Name, cooldown)
		if err != nil {
			// A history that cannot be read leaves the module cooling, which is the
			// safe answer, but it is not the answer the caller asked for.
			log.WithFields(log.Fields{"module": mod.Name, "error": err}).
				Debug("Could not read release history")
			continue
		}
		offer, churning := step(found, cooldown, app.churn, time.Now())
		if !churning {
			continue
		}
		if offer == "" {
			log.WithFields(log.Fields{
				"module":   mod.Name,
				"versions": len(found),
			}).Debugf("No release has settled within the newest %d versions", stepLimit)
			continue
		}
		// A step back to what is already installed is the ordinary outcome for a
		// module the project is up to date with: it is releasing faster than the
		// cooldown, and the newest settled version is the one already held. Nothing
		// is on offer, and saying so is not a failure.
		if !mod.Steppable(offer) {
			log.WithFields(log.Fields{
				"module":  mod.Name,
				"settled": offer,
			}).Debug("Newest settled release is the version already installed, so waiting")
			continue
		}
		if err := mod.StepBackTo(offer, found[slices.IndexFunc(found,
			func(r release) bool { return r.Version == offer })].Time); err != nil {
			log.WithFields(log.Fields{"module": mod.Name, "error": err}).
				Warn("Could not step back to a settled release")
			continue
		}
		log.WithFields(log.Fields{
			"module": mod.Name,
			"offer":  offer,
		}).Debug("Module is still releasing, so offering its newest settled version")
	}
	return nil
}
