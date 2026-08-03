package app

import (
	"testing"
	"time"
)

// TestUpdateWindowMasksTheClock checks that the cache key changes on a boundary rather than
// drifting with the moment.
//
// "go list -m -u" asks what upgrade exists right now, and the answer changes when upstream
// publishes -- which alters nothing on disk. So the key has to carry time: a go.mod checksum
// alone would keep reporting last week's answer indefinitely. Masking by the window means every
// run inside it shares a key, and the first run after it re-asks.
func TestUpdateWindowMasksTheClock(t *testing.T) {
	day := 24 * time.Hour
	at := func(iso string) time.Time {
		got, err := time.Parse(time.RFC3339, iso)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	for _, tc := range []struct {
		name   string
		window time.Duration
		a, b   string
		same   bool
	}{{
		// Within a day, the same key: asking twice in an afternoon is one question.
		name:   "same day",
		window: day,
		a:      "2026-08-03T00:00:01Z",
		b:      "2026-08-03T23:59:59Z",
		same:   true,
	}, {
		// Across midnight, a new key, so the run asks upstream again.
		name:   "next day",
		window: day,
		a:      "2026-08-03T23:59:59Z",
		b:      "2026-08-04T00:00:01Z",
		same:   false,
	}, {
		// A wider window holds more days.
		name:   "two days, within",
		window: 2 * day,
		a:      "2026-08-03T00:00:01Z",
		b:      "2026-08-04T23:00:00Z",
		same:   true,
	}, {
		name:   "two days, across",
		window: 2 * day,
		a:      "2026-08-03T00:00:01Z",
		b:      "2026-08-05T12:00:00Z",
		same:   false,
	}, {
		// No window means never reuse, so every moment is its own key.
		name:   "no window",
		window: 0,
		a:      "2026-08-03T00:00:01Z",
		b:      "2026-08-03T00:00:02Z",
		same:   false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			x := updateWindow(at(tc.a), tc.window)
			y := updateWindow(at(tc.b), tc.window)
			if (x == y) != tc.same {
				t.Errorf("updateWindow(%s)=%q and (%s)=%q, want same=%v",
					tc.a, x, tc.b, y, tc.same)
			}
		})
	}
}

// TestUpdateCacheRoundTrips checks that what the toolchain said about upgrades survives being
// stored and read back.
func TestUpdateCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := map[string]state{
		"github.com/aws/smithy-go": {
			Update:   "v1.27.6",
			Released: time.Date(2026, 7, 31, 18, 46, 10, 0, time.UTC),
		},
		"golang.org/x/text": {
			Deprecated: "use something else",
			Retracted:  []string{"withdrawn"},
		},
	}

	if err := storeUpdates(dir, "key1", want); err != nil {
		t.Fatalf("storeUpdates: %v", err)
	}
	got, ok := loadUpdates(dir, "key1")
	if !ok {
		t.Fatal("loadUpdates found nothing, want the stored state")
	}
	if len(got) != len(want) {
		t.Fatalf("loadUpdates() = %v, want %v", got, want)
	}
	// The upgrade and its date are the whole point of the entry.
	if s := got["github.com/aws/smithy-go"]; s.Update != "v1.27.6" || !s.Released.Equal(want["github.com/aws/smithy-go"].Released) {
		t.Errorf("got %+v, want the upgrade and its date", s)
	}
	// What the author said travels too, since it decides labels and policy outcomes.
	if s := got["golang.org/x/text"]; s.Deprecated == "" || len(s.Retracted) != 1 {
		t.Errorf("got %+v, want the deprecation and retraction", s)
	}

	// A different window is a different question.
	if _, ok := loadUpdates(dir, "key2"); ok {
		t.Error("loadUpdates hit on a different key, want a miss")
	}
}

// TestUpdateCacheIgnoresRubbish checks that an unreadable entry reads as a miss, so a truncated
// file costs a re-ask rather than a wrong answer about what is available.
func TestUpdateCacheIgnoresRubbish(t *testing.T) {
	dir := t.TempDir()
	writeAt(t, dir, updateCacheDir+"/bad.json", "{not json")
	if _, ok := loadUpdates(dir, "bad"); ok {
		t.Error("loadUpdates hit on an unreadable entry, want a miss")
	}
}
