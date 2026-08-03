package app

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/apex/log"

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
			log.WithError(err).Debug("Error closing the Go release list")
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

// checkGoVersion reports where a project's declared Go version breaks the release channel
// its policy states, or nil when it has nothing to say.
//
// Two independent bounds, and the directions are opposite. The channel bounds the go
// directive from above: "go 1.26" is a demand on whoever builds the module, so declaring it
// drops every consumer still on 1.25. A floor bounds it from below, which is about what the
// project itself needs. A library sets the first, an application the second, and both may
// be set.
//
// patched says the toolchain carries an advisory. A channel is a promise about
// conservatism, and an advisory outranks it: staying two patches back is a preference,
// while running a Go with a known hole is a problem. So the patch offset is waived and the
// project may move to the fixed release -- the same exemption the cooldown makes, and for
// the same reason.
//
// Nothing is said in three cases, each because a verdict needs warrant. A policy that did
// not ask gets no answer and costs no request. A project declaring nothing has said
// nothing. And a release list that could not be read leaves the window unknown, so whether
// a version sits inside it cannot be answered.
func checkGoVersion(rules *policy.Policy, declared string, patched bool) []violation {
	if rules == nil || declared == "" {
		return nil
	}
	var found []violation

	if channel, ok := rules.GoChannel(); ok {
		if action, ok := rules.Action(policy.CondGoUnsupported); ok {
			// An advisory in the toolchain waives the patch offset: the project has to
			// be able to reach the release that fixes it.
			if patched {
				channel.Patch = 0
			}
			body, err := goReleases()
			var published []policy.Release
			if err == nil {
				published, err = policy.ParseReleases(false, body)
			}
			if err != nil {
				log.WithError(err).Debug("Could not read the published Go releases")
			} else if ceiling, err := channel.Ceiling(versionsOf(published)); err != nil {
				log.WithError(err).Warn("Could not work out the newest supported Go release")
			} else if !policy.ChannelAllows(declared, ceiling) {
				detail := fmt.Sprintf("go.mod declares %s; the policy supports %s or older", declared, ceiling)
				if patched {
					detail += ", with the patch offset waived for an advisory"
				}
				found = append(found, violation{
					Module:    ToolchainName,
					Condition: policy.CondGoUnsupported,
					Detail:    detail,
					Remedy:    fmt.Sprintf("lower the go directive to %s, or widen the channel", ceiling),
					Action:    action,
				})
			}
		}
	}

	if floor, ok := rules.GoRequires(); ok {
		if action, ok := rules.Action(policy.CondGoTooOld); ok {
			if policy.GoBelow(declared, floor) {
				found = append(found, violation{
					Module:    ToolchainName,
					Condition: policy.CondGoTooOld,
					Detail:    fmt.Sprintf("go.mod declares %s; policy requires %s or newer", declared, floor),
					Remedy:    fmt.Sprintf("raise the go directive to %s", floor),
					Action:    action,
				})
			}
		}
	}
	return found
}

// versionsOf reduces the releases to their version strings, which is what the channel
// arithmetic compares.
func versionsOf(releases []policy.Release) []string {
	out := make([]string, 0, len(releases))
	for _, r := range releases {
		out = append(out, r.Version)
	}
	return out
}
