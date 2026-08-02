package module

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// TestAgeTextIsReadable checks that an age is rounded to something a person reads.
//
// An age is the difference between two instants, so it arrives with nanoseconds on
// it: "46h45m59.033004s" is technically the answer and useless as a column. Nothing
// is decided by the seconds, so they go.
func TestAgeTextIsReadable(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * 24 * time.Hour)()

	for _, tc := range []struct {
		name string
		ago  time.Duration
		want string
	}{{
		// Days divide exactly, so the unit carries it.
		name: "a few days",
		ago:  3*24*time.Hour + 17*time.Minute + 33*time.Second,
		want: "3d",
	}, {
		// Under a day, hours are what a reader wants, not hours and seconds.
		name: "under a day",
		ago:  5*time.Hour + 42*time.Minute + 19*time.Second,
		want: "5h",
	}, {
		name: "under an hour",
		ago:  42*time.Minute + 19*time.Second,
		want: "42m",
	}, {
		name: "just published",
		ago:  30 * time.Second,
		want: "30s",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
			m.Released = now.Add(-tc.ago)
			if got := m.AgeText(); got != tc.want {
				t.Errorf("AgeText() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFilterHidesCooling checks that a release still settling is kept out of a
// listing unless it was asked for.
//
// Not recommending it and listing it anyway would put the reader back where they
// started, deciding for themselves which rows are safe. Naming the key says the
// question was asked deliberately.
func TestFilterHidesCooling(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	fresh := mod(t, "example.com/fresh", "v1.0.0", "v1.1.0", false)
	fresh.Released = now.Add(-1 * day)
	settled := mod(t, "example.com/settled", "v1.0.0", "v1.1.0", false)
	settled.Released = now.Add(-30 * day)
	all := []Module{fresh, settled}

	for _, tc := range []struct {
		spec string
		want []string
	}{{
		// The default withholds it.
		spec: "",
		want: []string{"example.com/settled"},
	}, {
		// Asked for, so both appear.
		spec: "+cooldown",
		want: []string{"example.com/fresh", "example.com/settled"},
	}, {
		// Named alone, only the ones still settling.
		spec: "cooldown",
		want: []string{"example.com/fresh"},
	}} {
		t.Run(tc.spec, func(t *testing.T) {
			f, err := ParseFilter(tc.spec, DefaultFilters())
			if err != nil {
				t.Fatalf("ParseFilter(%q): %v", tc.spec, err)
			}
			var got []string
			for _, m := range Apply(all, f) {
				got = append(got, m.Name)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCooling checks which versions are too fresh to recommend.
//
// A release published hours ago has had no time to be found broken, so it is not
// recommended yet. What counts as long enough is the caller's to set; what is not
// negotiable is that an unknown date reads as unknown, and that a reachable advisory
// outranks the risk of a fresh release.
func TestCooling(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		released time.Time
		cooldown time.Duration
		reached  int
		want     bool
	}{{
		name:     "published today",
		released: now.Add(-2 * time.Hour),
		cooldown: 7 * day,
		want:     true,
	}, {
		name:     "published within the period",
		released: now.Add(-3 * day),
		cooldown: 7 * day,
		want:     true,
	}, {
		// Exactly at the boundary has waited long enough: the period is how long to
		// wait, not how long to keep waiting.
		name:     "published exactly a period ago",
		released: now.Add(-7 * day),
		cooldown: 7 * day,
		want:     false,
	}, {
		name:     "long settled",
		released: now.Add(-90 * day),
		cooldown: 7 * day,
		want:     false,
	}, {
		// An unknown date is not a fresh one. Treating zero as "just published"
		// would withhold every module the toolchain said nothing about.
		name:     "no date at all",
		released: time.Time{},
		cooldown: 7 * day,
		want:     false,
	}, {
		// A known vulnerability outranks the risk of a fresh release: waiting keeps
		// the advisory, and taking the upgrade is the point.
		name:     "fresh, but an advisory is reached",
		released: now.Add(-1 * time.Hour),
		cooldown: 7 * day,
		reached:  1,
		want:     false,
	}, {
		// An advisory that is present but not reached does not exempt it, since
		// nothing is calling the vulnerable code.
		name:     "fresh, with an advisory that is not reached",
		released: now.Add(-1 * time.Hour),
		cooldown: 7 * day,
		reached:  0,
		want:     true,
	}, {
		// No cooldown asked for, so nothing is withheld.
		name:     "cooldown disabled",
		released: now.Add(-1 * time.Hour),
		cooldown: 0,
		want:     false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			defer SetClock(func() time.Time { return now })()
			defer setCooldown(tc.cooldown)()

			m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
			m.Released = tc.released
			m.Reachable = tc.reached
			if tc.reached > 0 {
				m.Vulns = []string{"CVE-0000-0001"}
			}

			if got := m.Cooling(); got != tc.want {
				t.Errorf("Cooling() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAgeReportsHowOld checks that a module can say how long its version has been
// out, which is what the cooldown compares.
func TestAgeReportsHowOld(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()

	m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
	m.Released = now.Add(-3 * 24 * time.Hour)
	if got, want := m.Age(), 3*24*time.Hour; got != want {
		t.Errorf("Age() = %v, want %v", got, want)
	}

	// An unknown date has no age rather than an age of forever.
	m.Released = time.Time{}
	if got := m.Age(); got != 0 {
		t.Errorf("Age() = %v, want zero for an unknown date", got)
	}
}

// TestDefaultSortDemotesCooling checks that a release still settling sorts below one
// that has, and that an advisory still outranks the demotion.
//
// A cooling module is not recommended, so it belongs at the bottom -- but a reachable
// advisory is the reason the listing exists, and the cooldown must not bury it. The
// cooldown key sits after the advisory key for exactly that reason.
func TestDefaultSortDemotesCooling(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	settled := mod(t, "example.com/settled", "v1.0.0", "v1.1.0", false)
	settled.Released = now.Add(-30 * day)
	fresh := mod(t, "example.com/fresh", "v1.0.0", "v1.1.0", false)
	fresh.Released = now.Add(-1 * day)
	fresher := mod(t, "example.com/fresher", "v1.0.0", "v1.1.0", false)
	fresher.Released = now.Add(-2 * time.Hour)

	sorter, err := ParseSort("", DefaultSorts())
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	got := []Module{fresher, fresh, settled}
	slices.SortStableFunc(got, sorter.Compare)

	// Settled leads, then the cooling ones oldest first, since those are closest to
	// being ready.
	want := []string{"example.com/settled", "example.com/fresh", "example.com/fresher"}
	var names []string
	for _, m := range got {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

// TestCoolingDoesNotOutrankAnAdvisory checks that a fresh release carrying a reached
// advisory still leads, since the exemption keeps it out of the cooling group
// entirely.
func TestCoolingDoesNotOutrankAnAdvisory(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	vulnerable := mod(t, "example.com/vulnerable", "v1.0.0", "v1.1.0", false)
	vulnerable.Released = now.Add(-1 * time.Hour)
	vulnerable.Vulns = []string{"CVE-0000-0001"}
	vulnerable.Reachable = 1

	quiet := mod(t, "example.com/quiet", "v1.0.0", "v1.1.0", false)
	quiet.Released = now.Add(-30 * day)

	sorter, err := ParseSort("", DefaultSorts())
	if err != nil {
		t.Fatalf("ParseSort: %v", err)
	}
	got := []Module{quiet, vulnerable}
	slices.SortStableFunc(got, sorter.Compare)

	if got[0].Name != "example.com/vulnerable" {
		t.Errorf("got %s first, want the reached advisory to lead", got[0].Name)
	}
}

// TestCoolingCarriesALabel checks that a module still settling says so in the label
// column, and that the letter sits where the default sort puts it.
//
// The letters read as the priority the listing is ordered by, so a cooling module's
// mark belongs between how it is required and whether another upgrade handles it.
func TestCoolingCarriesALabel(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
	m.Released = now.Add(-1 * day)
	if got, want := m.LabelText(), "C"; got != want {
		t.Errorf("LabelText() = %q, want %q", got, want)
	}

	// Among the others, in the order the listing is sorted by.
	m.Fixes = []string{"example.com/other"}
	m.Indirect = true
	m.FixedBy = []string{"example.com/other"}
	m.Deprecated = "gone"
	if got, want := m.LabelText(), "FiCTD"; got != want {
		t.Errorf("LabelText() = %q, want %q", got, want)
	}

	// Settled, so the letter goes.
	m.Released = now.Add(-30 * day)
	if got := m.LabelText(); strings.Contains(got, "C") {
		t.Errorf("LabelText() = %q, want no cooldown label once settled", got)
	}
}

// TestLegendExplainsCooling checks that the letter is explained where it is used, so
// a reader meeting "C" is not left guessing.
func TestLegendExplainsCooling(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
	m.Released = now.Add(-1 * day)

	got := escapes.ReplaceAllString(Legend([]Module{m}), "")
	if !strings.Contains(got, "C ") {
		t.Errorf("legend %q does not explain the cooldown label", got)
	}
	if !strings.Contains(got, "recently") {
		t.Errorf("legend %q does not say what the label means", got)
	}
}

// TestCooldownText checks the hybrid column: how long a version has been out while
// it is still settling, and the date it landed once it has.
//
// While a release is cooling, how long it has left is the actionable fact and an age
// answers it. Once settled the age keeps climbing and says nothing, so the date takes
// over -- a fixed value that reads the same on every run.
func TestCooldownText(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		released time.Time
		want     string
	}{{
		name:     "cooling, so how old it is",
		released: now.Add(-3 * day),
		want:     "3d",
	}, {
		name:     "cooling, less than a day",
		released: now.Add(-5 * time.Hour),
		want:     "5h",
	}, {
		name:     "settled, so the date it landed",
		released: now.Add(-30 * day),
		want:     "2026-07-03",
	}, {
		// Nothing to say, which keeps the column out of a listing that needs it for
		// nothing.
		name:     "unknown",
		released: time.Time{},
		want:     "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			defer SetClock(func() time.Time { return now })()
			defer setCooldown(7 * day)()

			m := mod(t, "example.com/m", "v1.0.0", "v1.1.0", false)
			m.Released = tc.released
			if got := m.CooldownText(); got != tc.want {
				t.Errorf("CooldownText() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAgeAndReleaseTextAreAbsolute checks that the other two columns say one thing
// each, whatever the cooldown makes of the module.
//
// The hybrid column is for reading a listing at a glance; these two are for a reader
// who wants the age or the date regardless.
func TestAgeAndReleaseTextAreAbsolute(t *testing.T) {
	day := 24 * time.Hour
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer SetClock(func() time.Time { return now })()
	defer setCooldown(7 * day)()

	cooling := mod(t, "example.com/fresh", "v1.0.0", "v1.1.0", false)
	cooling.Released = now.Add(-2 * day)
	settled := mod(t, "example.com/settled", "v1.0.0", "v1.1.0", false)
	settled.Released = now.Add(-30 * day)

	// Always relative, whether or not the module is cooling. The largest unit that
	// divides wins, so thirty days is a month rather than thirty days.
	if got, want := cooling.AgeText(), "2d"; got != want {
		t.Errorf("AgeText() = %q, want %q", got, want)
	}
	if got, want := settled.AgeText(), "1mo"; got != want {
		t.Errorf("AgeText() = %q, want %q", got, want)
	}
	// Always absolute.
	if got, want := cooling.ReleaseText(), "2026-07-31"; got != want {
		t.Errorf("ReleaseText() = %q, want %q", got, want)
	}
	if got, want := settled.ReleaseText(), "2026-07-03"; got != want {
		t.Errorf("ReleaseText() = %q, want %q", got, want)
	}

	// An unknown date leaves both empty rather than inventing a value.
	unknown := mod(t, "example.com/unknown", "v1.0.0", "v1.1.0", false)
	if got := unknown.AgeText(); got != "" {
		t.Errorf("AgeText() = %q, want empty", got)
	}
	if got := unknown.ReleaseText(); got != "" {
		t.Errorf("ReleaseText() = %q, want empty", got)
	}
}
