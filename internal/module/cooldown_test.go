package module

import (
	"testing"
	"time"
)

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
			defer setClock(func() time.Time { return now })()
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
// out, which is what the listing shows and what the cooldown compares.
func TestAgeReportsHowOld(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	defer setClock(func() time.Time { return now })()

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
