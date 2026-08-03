package app

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
)

// timing reports how long each phase of a run took.
//
// Package-level rather than threaded through every caller, in the same way the spinner is:
// the phases are bracketed by progress, which every expensive step already defers, so the
// measurement belongs where the bracket is rather than at each of the dozen call sites.
var timing struct {
	sync.Mutex
	on bool
	// now is what elapsed time is measured against, so a test can decide what "later"
	// means.
	now func() time.Time
	// total accumulates by phase, since a phase runs once per directory and per build
	// configuration -- what a reader wants is what the whole run spent on it.
	total map[string]time.Duration
	calls map[string]int
	order []string
}

func init() {
	timing.now = time.Now
	timing.total = map[string]time.Duration{}
	timing.calls = map[string]int{}
}

// SetTiming asks for a timing report, and is called once at startup.
func SetTiming(on bool) {
	timing.Lock()
	defer timing.Unlock()
	timing.on = on
}

// record adds a phase's elapsed time to the run's total.
//
// The label is stripped of its trailing ellipsis and of anything in parentheses, so
// "Scanning opensearch-go (0/4)" and "Scanning osotel (2/4)" accumulate as one phase rather
// than as a dozen. What a reader wants is the time scanning cost, not each spinner's share.
func record(label string, took time.Duration) {
	timing.Lock()
	defer timing.Unlock()
	if !timing.on {
		return
	}
	phase := phaseName(label)
	if _, had := timing.total[phase]; !had {
		timing.order = append(timing.order, phase)
	}
	timing.total[phase] += took
	timing.calls[phase]++
}

// phaseName reduces a progress message to the phase it belongs to.
func phaseName(label string) string {
	name := strings.TrimSpace(label)
	if at := strings.IndexByte(name, '('); at > 0 {
		name = name[:at]
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), "...")
	// A label naming the directory it is working in is still the same phase, so the name
	// is dropped. Only a directory, though: "Inspecting dependencies" says what the phase
	// does rather than where, and the word after the verb is the giveaway -- a phase names
	// its own subject in the plural or with a preposition, never a bare noun.
	if head, rest, found := strings.Cut(name, " "); found && (head == "Inspecting" || head == "Scanning") {
		switch rest {
		case "dependencies", "for vulnerabilities":
		default:
			name = head
		}
	}
	return name
}

// ReportTiming writes what each phase of the run cost, slowest first.
//
// Slowest first because that is the order a reader acts on: the phase at the top is the one
// worth caching or narrowing, and the rest is noise until it is dealt with.
func ReportTiming() {
	timing.Lock()
	defer timing.Unlock()
	if !timing.on || len(timing.order) == 0 {
		return
	}
	phases := append([]string(nil), timing.order...)
	sort.SliceStable(phases, func(i, j int) bool {
		return timing.total[phases[i]] > timing.total[phases[j]]
	})
	var run time.Duration
	for _, p := range phases {
		run += timing.total[p]
	}
	for _, p := range phases {
		took := timing.total[p]
		entry := log.WithFields(log.Fields{
			"took":  took.Round(time.Millisecond),
			"share": fmt.Sprintf("%.0f%%", 100*float64(took)/float64(max(run, 1))),
		})
		if n := timing.calls[p]; n > 1 {
			entry = entry.WithField("passes", n)
		}
		entry.Infof("Timing: %s", p)
	}
}

// exit ends the process. A variable so a test can watch what a quit does without being ended
// by it.
var exit = os.Exit

// quit ends a run a reader chose to abandon, reporting the timing first.
//
// os.Exit runs no deferred function, so the report Run defers never fired on any path that
// quits -- which is every path someone takes when they change their mind, including the run
// they were measuring. Every such path goes through here so the rule cannot be forgotten at
// the next one.
//
// Zero, since giving up is not a failure: a reader who declines the upgrades has done nothing
// wrong and a script should not treat it as an error.
func quit() {
	ReportTiming()
	log.Info("Bye")
	exit(0)
}

// stop ends a run that failed, reporting the timing first.
//
// Same reasoning as quit: a failed run is one whose timing is most worth seeing, since the
// phase that broke is often the slow one.
func stop(code int) {
	ReportTiming()
	exit(code)
}
