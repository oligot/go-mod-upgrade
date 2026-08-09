package app

import (
	"context"
	"io"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
)

// setProgressOutput sends both the spinners and the log to w, and returns a
// function restoring what was there before.
//
// The two have to share a destination for a test to see how they are ordered
// against each other, which is the whole of what the coordination does. They share
// it through the same console a run builds, so that what a test asserts about an
// entry landing beside a spinner is what a reader would be shown.
//
// The level is lowered to trace for the duration: the global level survives between
// tests, and a test asserting on a debug entry should not depend on which test ran
// before it.
func setProgressOutput(w io.Writer) (restore func()) {
	prevOut, prevLog, prevLevel := progressOut, log.Logger, zerolog.GlobalLevel()
	progressOut = w
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = zerolog.New(humanWriter(newConsole(w), false))
	return func() {
		progressOut = prevOut
		log.Logger = prevLog
		zerolog.SetGlobalLevel(prevLevel)
	}
}

// setLogForReader says whether log entries are being written for a person, and
// returns a function restoring what was there.
//
// It decides how a period in a field is spelled, which a test asserting on either
// spelling has to settle rather than inherit from whichever test ran before it.
func setLogForReader(on bool) (restore func()) {
	prev := logForReader
	logForReader = on
	return func() { logForReader = prev }
}

// setStderr captures what is written beside the listing -- the legend, and the policy
// report -- and returns a function restoring what was there.
//
// color.Error rather than os.Stderr: that is the writer both take, and swapping it is
// what lets a test read them. Colour is turned off for the duration, so an assertion
// is made against the text rather than against the escapes wrapping it.
func setStderr(w io.Writer) (restore func()) {
	prevOut, prevNoColor := color.Error, color.NoColor
	color.Error, color.NoColor = w, true
	return func() {
		color.Error, color.NoColor = prevOut, prevNoColor
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

// setVulndbPrepare answers the database preparation from a function rather than the network,
// and returns a function restoring what was there.
//
// The result is remembered for the run, so the memory is cleared too: a test that changed the
// answer would otherwise see whatever an earlier one had already prepared.
func setVulndbPrepare(fn func() (string, error)) (restore func()) {
	prev := vulndbPrepare
	vulndbPrepare = func(context.Context) (string, error) { return fn() }
	clearPrepared()
	return func() {
		vulndbPrepare = prev
		clearPrepared()
	}
}

func clearPrepared() {
	prepared.Lock()
	prepared.dir, prepared.err, prepared.done = "", nil, false
	prepared.Unlock()
}

// setStdout sends the listing to w, and returns a function restoring what was
// there before.
//
// What a format wrote is the only account of what it decided, there being no
// return value to read: the writers log their errors and hand back nothing.
func setStdout(w io.Writer) (restore func()) {
	prev := stdout
	stdout = w
	return func() { stdout = prev }
}

// setAskVersion answers the version prompt from a function rather than a terminal,
// and returns a function restoring what was there before.
func setAskVersion(fn func(module.Module, []release, float64, *policy.Policy) (string, error)) (restore func()) {
	prev := askVersion
	askVersion = fn
	return func() { askVersion = prev }
}

// setCandidateRequires answers what the upgrades require from a function rather than
// the toolchain, and returns a function restoring what was there before.
//
// A failed lookup is what permitted's fail-open turns on, and provoking one for real
// would mean breaking the module cache the rest of the suite shares.
func setCandidateRequires(fn func(context.Context, string, []candidate) (map[string]requires, error)) (restore func()) {
	prev := readCandidateRequires
	readCandidateRequires = fn
	return func() { readCandidateRequires = prev }
}
