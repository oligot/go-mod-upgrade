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

// goReleasesURL is where Go publishes its releases. The default endpoint reports the
// supported ones -- the current release and the one before it -- which is the window a
// policy about "the last two releases" is asking about.
const goReleasesURL = "https://go.dev/dl/?mode=json"

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
	got  []string
	err  error
	done bool
}

// goReleases returns the supported Go releases, newest first, reading them once per run.
func goReleases() ([]string, error) {
	releases.Lock()
	defer releases.Unlock()
	if releases.done {
		return releases.got, releases.err
	}
	releases.done = true

	body, err := fetchGoReleases()
	if err != nil {
		releases.err = err
		return nil, err
	}
	releases.got, releases.err = policy.ParseReleases(body)
	return releases.got, releases.err
}

// checkGoVersion reports a project declaring a Go version older than the policy
// supports, or nil when it has nothing to say.
//
// Nothing is said in three cases, each for the same reason: a verdict has to be
// warranted. A policy that did not ask about Go versions gets no answer and costs no
// request. A project declaring nothing has said nothing, which is not the same as
// declaring something ancient. And a release list that could not be read leaves the
// window unknown, so whether a version is inside it is not a question that can be
// answered -- reporting a breach there would be a guess.
func checkGoVersion(rules *policy.Policy, declared string) *violation {
	if rules == nil {
		return nil
	}
	last, ok := rules.GoReleases()
	if !ok {
		return nil
	}
	action, ok := rules.Action(policy.CondGoUnsupported)
	if !ok {
		// The policy names a window but no rule responds to falling outside it, so
		// there is nothing to report.
		return nil
	}
	if declared == "" {
		return nil
	}

	supported, err := goReleases()
	if err != nil {
		log.WithError(err).Debug("Could not read the supported Go releases")
		return nil
	}
	floor, err := policy.GoFloor(supported, last)
	if err != nil {
		log.WithError(err).Debug("Could not work out the oldest supported Go release")
		return nil
	}
	if policy.GoSupported(declared, floor) {
		return nil
	}
	return &violation{
		Module:    ToolchainName,
		Condition: policy.CondGoUnsupported,
		Detail: fmt.Sprintf("policy supports the last %d Go releases, so %s or newer; go.mod declares %s",
			last, floor, declared),
		Action: action,
	}
}
