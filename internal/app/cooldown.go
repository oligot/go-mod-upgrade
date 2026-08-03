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
	"github.com/oligot/go-mod-upgrade/internal/policy"
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

// within keeps the releases inside the churn window, newest first.
//
// The window is what the caller already called recent activity, so it bounds what is
// worth offering: anything older is history rather than a candidate someone is
// choosing between. The order is the history's own, which history returns newest
// first.
func within(history []release, churn time.Duration, at time.Time) []release {
	var kept []release
	for _, r := range history {
		if at.Sub(r.Time) <= churn {
			kept = append(kept, r)
		}
	}
	return kept
}

// newestSettled returns the position of the newest release that has been out longer
// than the cooldown, or -1 when none has.
//
// That release is the one the tool recommends, so it is where a prompt's cursor
// belongs. A position rather than the release itself, since the caller needs it to
// place the cursor in the list it was given.
func newestSettled(candidates []release, cooldown time.Duration, at time.Time) int {
	for i, r := range candidates {
		if at.Sub(r.Time) >= cooldown {
			return i
		}
	}
	return -1
}

// What a prompt says about each version it offers.
//
// Three answers, and not the same kind of thing. A cooldown is a judgement about time
// that a reader may overrule once told the age; a policy is a rule someone wrote down,
// and a version it refuses is not a choice at all. Calling both "in cooldown" would
// flatten that.
const (
	// statusEligible is a version nothing objects to: settled, and permitted.
	//
	// Not "recommended" -- the tool is not endorsing it, only reporting that it clears
	// the cooldown the caller set.
	statusEligible = "eligible"
	// statusCooling is a release still inside the cooldown. A reader may take it
	// anyway, which is why the age is beside it.
	statusCooling = "in cooldown"
	// statusDenied is a version a policy refuses. Shown rather than hidden, since a
	// reader who cannot have the newest should be told why instead of wondering where
	// it went.
	statusDenied = "denied by policy"
)

// versionStatuses says why each candidate is or is not on offer, in the order given.
//
// A policy is consulted per version because it can refuse one and permit another --
// "allow": "<= 1.27.4" is a statement about versions, not about the module. A policy
// that covers the module but refuses nothing leaves the cooldown to decide.
func versionStatuses(mod module.Module, candidates []release, cooldown time.Duration, at time.Time, rules *policy.Policy) []string {
	out := make([]string, 0, len(candidates))
	for _, r := range candidates {
		out = append(out, versionStatus(mod, r, cooldown, at, rules))
	}
	return out
}

// versionStatus says why one candidate is or is not on offer.
func versionStatus(mod module.Module, r release, cooldown time.Duration, at time.Time, rules *policy.Policy) string {
	if rules != nil {
		if v, err := semver.NewVersion(r.Version); err == nil {
			// A policy refusing the version outranks the cooldown: one is a rule and
			// the other a judgement, and no reader may overrule the rule from here.
			switch rules.Check(mod.Name, v, mod.From).Verdict {
			case policy.Denied, policy.VersionDenied:
				return statusDenied
			}
		}
	}
	if at.Sub(r.Time) < cooldown {
		return statusCooling
	}
	return statusEligible
}

// firstEligible returns the position of the newest version nothing objects to, or -1
// when every candidate is refused or still cooling.
//
// That is where a prompt's cursor belongs. A version a policy denies cannot be the
// default however settled it is: starting there would offer as the obvious choice
// something the run would then fail on.
func firstEligible(statuses []string) int {
	return slices.Index(statuses, statusEligible)
}

// versionList renders the versions a reader chooses between, with a heading for them.
//
// The heading is built here rather than by the caller so its padding cannot drift from
// the rows it labels. The age is right-aligned, so a two-week gap and a one-day gap
// still line up.
func versionList(candidates []release, statuses []string, at time.Time) (heading string, options []string) {
	const ageWidth = 4
	width := len("VERSION")
	for _, r := range candidates {
		width = max(width, len(strings.TrimPrefix(r.Version, "v")))
	}

	// The age is right-aligned so a two-week gap and a one-day gap line up, which
	// means its heading has to be too -- padded left, it would sit a column off from
	// the values it labels.
	heading = fmt.Sprintf("%-*s  %*s  %s", width, "VERSION", ageWidth, "AGE", "STATUS")
	options = make([]string, 0, len(candidates))
	for i, r := range candidates {
		// The age is measured the same way a listing measures it, so the two agree.
		aged := module.Module{Released: r.Time}
		options = append(options, fmt.Sprintf("%-*s  %*s  %s",
			width, strings.TrimPrefix(r.Version, "v"), ageWidth, aged.AgeText(), statuses[i]))
	}
	return heading, options
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
//
// The candidates each stepped module was choosing between are returned, keyed by path,
// so a prompt can offer them without fetching the history a second time. They are kept
// in a map rather than on the Module because a release belongs to this package.
func (app *AppEnv) settle(ctx context.Context, dir string, modules []module.Module) (map[string][]release, error) {
	if app.churn <= 0 {
		return nil, nil
	}
	var cooling []int
	for i := range modules {
		if modules[i].Cooling() {
			cooling = append(cooling, i)
		}
	}
	if len(cooling) == 0 {
		return nil, nil
	}

	stop, err := progress(fmt.Sprintf("Checking release history (%d)", len(cooling)))
	if err != nil {
		return nil, err
	}
	defer stop()

	candidates := map[string][]release{}
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
		// What this module was choosing between, so a prompt can offer the same set
		// without fetching the history again. Only the churn window: anything older
		// is history rather than a candidate.
		if inside := within(found, app.churn, time.Now()); len(inside) > 1 {
			candidates[mod.Name] = inside
		}
	}
	return candidates, nil
}

// askVersions asks which version to take for each module that stepped back, and
// records the answers.
//
// A module with no candidates keeps what it was offered, which is the settled release
// the tool chose, so a history that could not be read costs nothing but the question.
func askVersions(modules []module.Module, candidates map[string][]release, pageSize float64, rules *policy.Policy) error {
	for i := range modules {
		mod := &modules[i]
		found := candidates[mod.Name]
		if !mod.Stepped() || len(found) < 2 {
			continue
		}
		chosen, err := chooseVersion(*mod, found, pageSize, rules)
		if err != nil {
			return err
		}
		if chosen == "" || chosen == mod.To.Original() {
			continue
		}
		at := found[slices.IndexFunc(found, func(r release) bool { return r.Version == chosen })].Time
		if err := mod.ChooseVersion(chosen, at); err != nil {
			return fmt.Errorf("%s: %w", mod.Name, err)
		}
	}
	return nil
}

// chooseVersion asks which version of a stepped module to install, starting on the one
// the tool recommends.
//
// The cursor and the selection both begin on the newest settled release, so a reader
// who agrees presses enter and is done. The cooling releases are listed above it with
// their ages, since the reader is the one who gets to weigh a fresh release against
// waiting -- but they have to be told which is which to do that.
//
// Returns the version chosen, or the empty string when there was nothing to ask.
func chooseVersion(mod module.Module, candidates []release, pageSize float64, rules *policy.Policy) (string, error) {
	at := time.Now()
	statuses := versionStatuses(mod, candidates, module.Cooldown(), at, rules)
	start := firstEligible(statuses)
	// Nothing to choose between, or nothing eligible to start from: leave the module
	// as it stands rather than opening a prompt with no sensible default.
	if len(candidates) < 2 || start < 0 {
		return "", nil
	}

	heading, options := versionList(candidates, statuses, at)
	// A version a policy refuses is shown so a reader knows why the newest is not on
	// offer, but it cannot be taken from here: the policy is where that decision was
	// recorded, so that is where it has to be changed. A guard rail rather than a
	// lock -- nothing stops someone editing the policy, the point is that doing so is
	// deliberate and leaves a diff.
	denied := map[int]struct{}{}
	for i, s := range statuses {
		if s == statusDenied {
			denied[i] = struct{}{}
		}
	}
	message := fmt.Sprintf("Which version of %s? It is still releasing, so %s is the newest that clears the cooldown",
		mod.Name, strings.TrimPrefix(candidates[start].Version, "v"))
	choice, answered, err := askSingle(message, heading, options, start, pageRows(pageSize), denied)
	if err != nil {
		return "", err
	}
	if !answered {
		log.Info("Bye")
		os.Exit(0)
	}
	if choice < 0 {
		return "", nil
	}
	return candidates[choice].Version, nil
}
