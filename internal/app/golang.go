package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"

	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// goReleasesURL is where Go publishes its releases.
//
// include=all rather than the default, which reports only the two current releases. A band
// counts patches, so it needs the history: without it a patch offset had nothing to step
// back to and failed with "nothing below 1.26.5 is published". Release candidates come with
// it and are filtered when they are not wanted, so one payload answers both.
const goReleasesURL = "https://go.dev/dl/?mode=json&include=all"

// fetchGoReleases reads the release list over the network. A variable so a test can
// answer without one.
var fetchGoReleases = func() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, goReleasesURL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching Go releases: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Trace().Err(err).Msg("Error closing the Go release list")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching Go releases: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// releases caches the list for the run.
//
// Go releases twice a year, so a list read a moment ago is as good as one read now.
// Without this a workspace of twenty members would make twenty identical requests to
// answer the same question. The error is cached too: a failure repeated per member is
// twenty failures reported for one problem.
var releases struct {
	sync.Mutex
	body []byte
	err  error
	done bool
}

// goReleases returns the published release list as go.dev gave it, read once per run.
//
// The bytes rather than the parsed releases, since whether release candidates belong in the
// answer is the policy's business and one payload serves both readings.
func goReleases() ([]byte, error) {
	releases.Lock()
	defer releases.Unlock()
	if releases.done {
		return releases.body, releases.err
	}
	releases.done = true

	body, err := fetchGoReleases()
	if err != nil {
		releases.err = err
		return nil, err
	}
	releases.body = body
	return releases.body, nil
}

// checkGoVersion reports a project declaring a Go version outside the band its policy
// supports, or nil when it has nothing to say.
//
// One finding rather than two, because a band has two edges and one meaning. Declaring
// something newer than the ceiling drops consumers the project promised to support, since the
// go directive is a demand on whoever builds the module. Declaring something older than the
// floor is outside the supported set, or carries an advisory the band excludes. Either way
// what has to change is the same directive.
//
// Nothing is said in three cases, each because a verdict needs warrant. A policy that did not
// ask gets no answer and costs no request. A project declaring nothing has said nothing. And
// a release list that could not be read leaves the band unresolved, so whether a version sits
// inside it cannot be answered.
func (app *AppEnv) checkGoVersion(ctx context.Context, rules *policy.Policy, declared string) []violation {
	if rules == nil || declared == "" {
		return nil
	}
	band, ok := rules.GoBand()
	if !ok {
		return nil
	}
	action, ok := rules.Action(policy.CondGoOutsideBand)
	if !ok {
		// The policy names a band but no rule responds to falling outside it.
		return nil
	}

	body, err := goReleases()
	if err != nil {
		log.Debug().Err(err).Msg("Could not read the published Go releases")
		return nil
	}
	published, err := policy.ParseReleases(band.AllowPrerelease, body)
	if err != nil {
		log.Debug().Err(err).Msg("Could not read the published Go releases")
		return nil
	}

	// Which releases carry an advisory, read from the cached database rather than from a
	// scan: govulncheck answers only for the toolchain it ran with, and the question here
	// is about the version go.mod declares.
	var unclean func(string) bool
	if band.ExcludeCVE {
		windows, err := app.stdlibAdvisories(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Could not read the advisories, so the band excludes none")
		} else {
			unclean = func(v string) bool {
				at, err := semver.NewVersion(v)
				if err != nil {
					return false
				}
				return affected(at, windows)
			}
		}
	}

	floor, ceiling, err := band.Resolve(versionsOf(published), unclean)
	if err != nil {
		log.Warn().Err(err).Msg("Could not resolve the supported Go band")
		return nil
	}
	if policy.BandAllows(declared, floor, ceiling) {
		return nil
	}

	// The resolved edges rather than the bounds that produced them: ">= 1.25.12" is what a
	// reader can act on, where ">=2" leaves them to work it out.
	why := ""
	if band.ExcludeCVE && unclean != nil {
		why = ", the floor having risen past the releases carrying advisories"
	}
	return []violation{{
		Module:    ToolchainName,
		Condition: policy.CondGoOutsideBand,
		Detail: fmt.Sprintf("go.mod declares %s; the policy supports %s to %s%s",
			declared, floor, ceiling, why),
		Remedy: fmt.Sprintf("set the go directive between %s and %s", floor, ceiling),
		Action: action,
	}}
}

// stdlibAdvisories returns the version ranges the standard library's advisories cover, every
// advisory's in one list.
//
// Read here rather than left to the scan, since a band that excludes advisories needs them
// whether or not a scan was asked for.
func (app *AppEnv) stdlibAdvisories(ctx context.Context) ([]window, error) {
	dir, err := app.vulndbDir(ctx)
	if err != nil {
		return nil, err
	}
	return stdlibWindows(dir)
}

// stdlibAdvisoriesByID returns the same ranges keyed by advisory identifier, for a caller
// deciding which advisories cover a version rather than whether any do. The toolchain row needs
// the identifier, to match a range against the advisory the scan reported.
func (app *AppEnv) stdlibAdvisoriesByID(ctx context.Context) (advisoryWindows, error) {
	dir, err := app.vulndbDir(ctx)
	if err != nil {
		return nil, err
	}
	return stdlibWindowsByID(dir)
}

// vulndbDir prepares the vulnerability database and reports which copy is in use.
//
// Through preparedVulndb rather than vulndbCache, so a run revalidates once however many
// readers it has, and an unreachable server is reported once rather than once per reader.
// Reported here so a policy-only run also learns how old the advisories are, through the same
// sync.Once as the scan.
func (app *AppEnv) vulndbDir(ctx context.Context) (string, error) {
	dir, err := preparedVulndb(ctx)
	if err != nil {
		return "", err
	}
	reportVulndb(dir)
	return dir, nil
}

// versionsOf reduces the releases to their version strings, which is what the band
// arithmetic compares.
func versionsOf(releases []policy.Release) []string {
	out := make([]string, 0, len(releases))
	for _, r := range releases {
		out = append(out, r.Version)
	}
	return out
}
