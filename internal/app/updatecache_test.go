package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)
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
			require.Equal(t, tc.same, x == y,
				"updateWindow(%s)=%q and (%s)=%q, want same=%v", tc.a, x, tc.b, y, tc.same)
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

	require.NoError(t, storeUpdates(dir, "key1", want), "storeUpdates")
	got, written, ok := loadUpdates(dir, "key1")
	require.True(t, ok, "loadUpdates found nothing, want the stored state")
	require.False(t, written.IsZero(), "want the time the answer was written")
	require.Len(t, got, len(want))
	// The upgrade and its date are the whole point of the entry.
	s := got["github.com/aws/smithy-go"]
	require.Equal(t, "v1.27.6", s.Update)
	require.True(t, s.Released.Equal(want["github.com/aws/smithy-go"].Released),
		"got %v, want the release date to survive", s.Released)
	// What the author said travels too, since it decides labels and policy outcomes.
	s = got["golang.org/x/text"]
	require.NotEmpty(t, s.Deprecated, "want the deprecation")
	require.Len(t, s.Retracted, 1, "want the retraction")

	// A different window is a different question.
	_, _, ok = loadUpdates(dir, "key2")
	require.False(t, ok, "loadUpdates hit on a different key, want a miss")
}

// TestUpdateCacheIgnoresRubbish checks that an unreadable entry reads as a miss, so a truncated
// file costs a re-ask rather than a wrong answer about what is available.
func TestUpdateCacheIgnoresRubbish(t *testing.T) {
	dir := t.TempDir()
	writeAt(t, dir, updateCacheDir+"/bad.json", "{not json")
	_, _, ok := loadUpdates(dir, "bad")
	require.False(t, ok, "loadUpdates hit on an unreadable entry, want a miss")
}

// TestUpdateCacheHoldsTheWholeAnswer checks that what the toolchain said about the installed
// versions is remembered too, not just the upgrades.
//
// I had thought the local half needed no window, on the grounds that versions and retractions
// describe the tree rather than the proxy. That is wrong: a retraction is declared in a *later*
// version's go.mod, so an author can withdraw a version tomorrow and nothing on disk changes.
// A deprecation is the same. So the whole answer expires together, and one entry holds it.
func TestUpdateCacheHoldsTheWholeAnswer(t *testing.T) {
	dir := t.TempDir()
	reqs := []requirement{{Path: "example.com/m", Version: "v1.0.0"}}
	window := updateWindow(time.Unix(0, 0), 24*time.Hour)

	want := map[string]state{"example.com/m": {
		Update:     "v1.1.0",
		Deprecated: "use something else",
		Retracted:  []string{"published prematurely"},
		Released:   time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC),
	}}
	saveUpgrades(dir, window, reqs, want)

	got, ok, age, why := loadUpgrades(dir, window, reqs)
	require.True(t, ok, "loadUpgrades found nothing, want the stored answer")
	require.Empty(t, why, "a hit has nothing to explain")
	require.True(t, age.known, "a hit knows how old it is")
	s := got["example.com/m"]
	// Every part of it, since a listing shows all four and a policy acts on three.
	require.Equal(t, "v1.1.0", s.Update)
	require.NotEmpty(t, s.Deprecated)
	require.Len(t, s.Retracted, 1)
	require.False(t, s.Released.IsZero(), "want the release date")

	// A changed requirement is a different question, so the entry does not answer it.
	moved := []requirement{{Path: "example.com/m", Version: "v1.0.1"}}
	_, ok, _, _ = loadUpgrades(dir, window, moved)
	require.False(t, ok, "loadUpgrades hit after the requirement moved, want a miss")
	// And so is the next window.
	later := updateWindow(time.Unix(0, 0).Add(48*time.Hour), 24*time.Hour)
	_, ok, _, _ = loadUpgrades(dir, later, reqs)
	require.False(t, ok, "loadUpgrades hit in a later window, want a miss")
}

// TestCacheAgeReportsWhatIsKnown checks that an age which could not be read says so rather than
// reading as an answer gathered this instant.
//
// "age=0s" on an entry of unknown date is the one rendering that makes a stale listing look
// current, which is the opposite of what reporting the age is for.
func TestCacheAgeReportsWhatIsKnown(t *testing.T) {
	tests := []struct {
		name string
		age  cacheAge
		want string
	}{{
		name: "unknown",
		age:  cacheAge{},
		want: "unknown",
	}, {
		// Zero is a real age for an answer gathered a moment ago, and is only reported
		// when the date was read.
		name: "just gathered",
		age:  cacheAge{known: true},
		want: "0s",
	}, {
		// Rounded, since nothing here is decided at finer precision.
		name: "rounded to the second",
		age:  cacheAge{of: 3*time.Hour + 2*time.Minute + 1500*time.Millisecond, known: true},
		want: "3h2m2s",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.age.String())
		})
	}
}

// TestLoadUpgradesReportsTheAgeOfWhatItReturns checks that a reused answer carries how old it is,
// measured from when it was written.
//
// The flag alone does not say whether a listing is current: an answer from an hour ago and one
// from just under the window mean different things to a reader deciding whether to trust it.
func TestLoadUpgradesReportsTheAgeOfWhatItReturns(t *testing.T) {
	dir := t.TempDir()
	reqs := []requirement{{Path: "example.com/m", Version: "v1.0.0"}}
	window := updateWindow(time.Unix(0, 0), 24*time.Hour)
	saveUpgrades(dir, window, reqs, map[string]state{"example.com/m": {Update: "v1.1.0"}})

	// Backdated on disk, since the age is read from the entry rather than from anything the
	// process remembers -- a second run is the case this reports on.
	at := filepath.Join(dir, updateCacheDir, updateKey(reqs, window)+".json")
	backdated := time.Now().Add(-90 * time.Minute)
	require.NoError(t, os.Chtimes(at, backdated, backdated))

	_, ok, age, _ := loadUpgrades(dir, window, reqs)
	require.True(t, ok)
	require.True(t, age.known, "want the age of the entry")
	// A window either side of the hour and a half, so a slow test does not fail on timing.
	require.InDelta(t, 90*time.Minute, age.of, float64(time.Minute),
		"want the age measured from when the entry was written")

	// A file dated in the future reads as current rather than as a negative age, which would
	// render as "-1h0m0s" and read as a release yet to happen.
	ahead := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(at, ahead, ahead))
	_, ok, age, _ = loadUpgrades(dir, window, reqs)
	require.True(t, ok)
	require.Equal(t, "0s", age.String(), "want a future entry clamped to zero")
}

// TestLoadUpgradesSaysWhyItFetches checks that a miss carries a reason to log, and that the
// reason distinguishes having no cache from having no recent answer in one.
//
// The two are different situations for a reader: --cache=false fetches every run by design,
// while a cold entry fetches once. A single reason for both would report a deliberate choice as
// though something had expired.
func TestLoadUpgradesSaysWhyItFetches(t *testing.T) {
	reqs := []requirement{{Path: "example.com/m", Version: "v1.0.0"}}
	window := updateWindow(time.Unix(0, 0), 24*time.Hour)

	tests := []struct {
		name   string
		cache  string
		window string
		want   string
	}{{
		// --cache=false and a cache that could not be located both arrive as an empty
		// directory, and neither consulted an entry.
		name:   "caching declined",
		cache:  "",
		window: window,
		want:   "no cache to answer from",
	}, {
		// --cache-for=0 leaves nothing to reuse, so the window is empty.
		name:   "no window to reuse",
		cache:  t.TempDir(),
		window: "",
		want:   "no cache to answer from",
	}, {
		// A cache with no entry for these requirements.
		name:   "nothing stored",
		cache:  t.TempDir(),
		window: window,
		want:   "no recent answer for these requirements",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, _, why := loadUpgrades(tc.cache, tc.window, reqs)
			require.False(t, ok, "want a miss")
			require.Equal(t, tc.want, why)
		})
	}

	// Every miss says something, since the reason is logged and an empty field would read as
	// a fetch with no cause.
	for _, tc := range tests {
		_, _, _, why := loadUpgrades(tc.cache, tc.window, reqs)
		require.NotEmpty(t, why, "%s: a miss with no reason", tc.name)
	}
}
