package app

import (
	"strings"
	"testing"
	"time"
)

// TestTimingReportsEachPhase checks that every phase records how long it took, so a slow run
// says where the time went rather than leaving it to be guessed at.
//
// Reported at the end rather than as each phase finishes: a per-phase line would interleave
// with the spinner it is measuring, and what a reader wants is the phases ranked against each
// other, which is only knowable once they have all run.
func TestTimingReportsEachPhase(t *testing.T) {
	var out strings.Builder
	defer setProgressOutput(&out)()
	defer setTiming(true)()

	at := time.Unix(0, 0)
	defer setTimingClock(func() time.Time { return at })()

	for _, phase := range []struct {
		label string
		took  time.Duration
	}{
		{"Discovering modules...", 500 * time.Millisecond},
		{"Scanning for vulnerabilities", 4 * time.Second},
	} {
		stop, err := progress(phase.label)
		if err != nil {
			t.Fatalf("progress: %v", err)
		}
		at = at.Add(phase.took)
		stop()
	}
	ReportTiming()

	got := out.String()
	for _, want := range []string{"Discovering modules", "Scanning for vulnerabilities", "4s", "500ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("output %q does not mention %q", got, want)
		}
	}
	// Slowest first, since that is the phase worth acting on.
	if strings.Index(got, "Scanning") > strings.Index(got, "Discovering") {
		t.Errorf("output %q lists the faster phase first, want slowest first", got)
	}
	// And the share of the run, so a phase can be weighed against the whole.
	if !strings.Contains(got, "89%") {
		t.Errorf("output %q does not report each phase's share", got)
	}
}

// TestTimingIsSilentByDefault checks that timing costs nothing when it was not asked for.
//
// A listing is the product; how long each phase took is diagnostic, so it stays out of the
// way until someone is looking for it.
func TestTimingIsSilentByDefault(t *testing.T) {
	var out strings.Builder
	defer setProgressOutput(&out)()

	stop, err := progress("Discovering modules...")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	stop()
	ReportTiming()

	if strings.Contains(out.String(), "took") {
		t.Errorf("output %q reports timing, want it silent without --timing", out.String())
	}
}

// TestTimingStopIsIdempotent checks that a phase stopped twice is reported once.
//
// stop is deferred and sometimes also called explicitly, so it has to be safe to call twice --
// and a phase appearing twice in a timing report would misattribute the total.
func TestTimingStopIsIdempotent(t *testing.T) {
	var out strings.Builder
	defer setProgressOutput(&out)()
	defer setTiming(true)()

	at := time.Unix(0, 0)
	defer setTimingClock(func() time.Time { return at })()

	stop, err := progress("Scanning")
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	at = at.Add(time.Second)
	stop()
	stop()
	ReportTiming()

	if n := strings.Count(out.String(), "Scanning"); n != 1 {
		t.Errorf("the phase is reported %d times, want once", n)
	}
}

// TestPhaseNameGroupsRelatedLabels checks that the labels a phase draws collapse to one name.
//
// A phase runs once per directory and per build configuration, and names the directory as it
// goes: "Scanning osotel (2/4)". Reported label by label it would be a dozen lines each with a
// fraction of the total, when what a reader wants is what scanning cost.
func TestPhaseNameGroupsRelatedLabels(t *testing.T) {
	for _, tc := range []struct{ label, want string }{
		{"Discovering modules...", "Discovering modules"},
		{"Discovering tool modules...", "Discovering tool modules"},
		{"Scanning for vulnerabilities", "Scanning for vulnerabilities"},
		{"Checking release history (4)", "Checking release history"},
		// The directory is not the phase.
		{"Inspecting opensearch-go", "Inspecting"},
		{"Inspecting osotel (2/4)", "Inspecting"},
		{"Scanning osprom (1/4)", "Scanning"},
		// No trailing space where the name was cut away.
		{"Inspecting dependencies", "Inspecting dependencies"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := phaseName(tc.label)
			if got != tc.want {
				t.Errorf("phaseName(%q) = %q, want %q", tc.label, got, tc.want)
			}
			if got != strings.TrimSpace(got) {
				t.Errorf("phaseName(%q) = %q, want no surrounding space", tc.label, got)
			}
		})
	}
}
