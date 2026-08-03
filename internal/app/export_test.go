package app

import (
	"io"
	"time"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/briandowns/spinner"
)

// setProgressOutput sends both the spinners and the log handler to w, and returns
// a function restoring what was there before.
//
// The two have to share a destination for a test to see how they are ordered
// against each other, which is the whole of what the coordination does.
func setProgressOutput(w io.Writer) (restore func()) {
	prevOut, prevLog := progressOut, log.Log
	progressOut = w
	log.SetHandler(LogHandler(logcli.New(w)))
	return func() {
		progressOut = prevOut
		log.Log = prevLog
	}
}

// holdForTest registers s as the spinner drawing, without starting it.
//
// draw starts a spinner and registers it only if it drew, which needs a terminal
// the tests do not have. Registering directly stands in for that, so what an
// entry does about a drawing spinner can still be checked.
func holdForTest(s *spinner.Spinner) (release func()) {
	spinning.Lock()
	prev := spinning.at
	spinning.at = s
	spinning.Unlock()
	return func() {
		spinning.Lock()
		spinning.at = prev
		spinning.Unlock()
	}
}

// setGoReleasesFetch answers the release list from a function rather than the network,
// and returns a function restoring what was there.
//
// The list is cached for the run, so the cache is cleared too: a test that changed the
// answer would otherwise see whatever an earlier one had already fetched.
func setGoReleasesFetch(fetch func() ([]byte, error)) (restore func()) {
	prev := fetchGoReleases
	fetchGoReleases = fetch
	releases.Lock()
	releases.body, releases.err, releases.done = nil, nil, false
	releases.Unlock()
	return func() {
		fetchGoReleases = prev
		releases.Lock()
		releases.body, releases.err, releases.done = nil, nil, false
		releases.Unlock()
	}
}

// setTiming turns the timing report on, and returns a function restoring what was there.
func setTiming(on bool) (restore func()) {
	timing.Lock()
	prev := timing.on
	timing.on = on
	timing.total, timing.calls, timing.order = map[string]time.Duration{}, map[string]int{}, nil
	timing.Unlock()
	return func() {
		timing.Lock()
		timing.on = prev
		timing.total, timing.calls, timing.order = map[string]time.Duration{}, map[string]int{}, nil
		timing.Unlock()
	}
}

// setTimingClock decides what elapsed time is measured against, so a test can say what
// "later" means rather than sleeping.
func setTimingClock(clock func() time.Time) (restore func()) {
	timing.Lock()
	prev := timing.now
	timing.now = clock
	timing.Unlock()
	return func() {
		timing.Lock()
		timing.now = prev
		timing.Unlock()
	}
}

// setExit replaces the process exit, so a test can watch what a quit does without being ended
// by it.
func setExit(fn func(int)) (restore func()) {
	prev := exit
	exit = fn
	return func() { exit = prev }
}
