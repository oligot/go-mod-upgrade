package app

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
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

// TestUpdateCacheRoundTrips checks that what the toolchain said about one module survives being
// stored and read back.
func TestUpdateCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		key  string
		want state
	}{{
		// The upgrade and its date are the whole point of the entry.
		name: "an upgrade and when it was published",
		key:  "key1",
		want: state{
			Update:   "v1.27.6",
			Released: time.Date(2026, 7, 31, 18, 46, 10, 0, time.UTC),
		},
	}, {
		// What the author said travels too, since it decides labels and policy outcomes.
		name: "what the author withdrew",
		key:  "key2",
		want: state{
			Deprecated: "use something else",
			Retracted:  []string{"withdrawn"},
		},
	}, {
		// A module with nothing newer is a real answer, and one that must survive as
		// itself: read back as a miss it would be re-queried every run.
		name: "already at the newest version",
		key:  "key3",
		want: state{Released: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, storeAnswer(dir, tc.key, tc.want), "storeAnswer")

			got, written, ok := loadAnswer(dir, tc.key)
			require.True(t, ok, "loadAnswer found nothing, want the stored state")
			require.False(t, written.IsZero(), "want the time the answer was written")
			require.Equal(t, tc.want.Update, got.Update)
			require.Equal(t, tc.want.Deprecated, got.Deprecated)
			require.Equal(t, tc.want.Retracted, got.Retracted)
			require.True(t, got.Released.Equal(tc.want.Released),
				"got %v, want the release date to survive", got.Released)
		})
	}

	// A key nothing was stored under is a miss.
	_, _, ok := loadAnswer(dir, "absent")
	require.False(t, ok, "loadAnswer hit on a key never written, want a miss")
}

// TestUpdateCacheIgnoresRubbish checks that an unreadable entry reads as a miss, so a truncated
// file costs a re-ask rather than a wrong answer about what is available.
func TestUpdateCacheIgnoresRubbish(t *testing.T) {
	dir := t.TempDir()
	writeAt(t, dir, updateCacheDir+"/bad.json", "{not json")
	_, _, ok := loadAnswer(dir, "bad")
	require.False(t, ok, "loadAnswer hit on an unreadable entry, want a miss")
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

	got, missing, st, why := loadUpgrades(dir, window, reqs)
	require.Empty(t, missing, "want nothing left to ask")
	require.Empty(t, why, "a hit has nothing to explain")
	require.True(t, st.age().known, "a hit knows how old it is")
	s := got["example.com/m"]
	// Every part of it, since a listing shows all four and a policy acts on three.
	require.Equal(t, "v1.1.0", s.Update)
	require.NotEmpty(t, s.Deprecated)
	require.Len(t, s.Retracted, 1)
	require.False(t, s.Released.IsZero(), "want the release date")

	// The version is part of the key, since what is newer than one version is not what is
	// newer than another.
	moved := []requirement{{Path: "example.com/m", Version: "v1.0.1"}}
	_, missing, _, _ = loadUpgrades(dir, window, moved)
	require.Equal(t, moved, missing, "want the moved requirement left to ask about")
	// And so is the next window.
	later := updateWindow(time.Unix(0, 0).Add(48*time.Hour), 24*time.Hour)
	_, missing, _, _ = loadUpgrades(dir, later, reqs)
	require.Equal(t, reqs, missing, "want a later window asking again")
}

// TestLoadUpgradesAsksOnlyAboutWhatMoved is the point of keying per module: editing one line of
// go.mod costs a query for that line.
//
// Keyed on the whole require block, one changed version missed the only entry there was, and a run
// re-queried every module beside it at around 60ms each.
func TestLoadUpgradesAsksOnlyAboutWhatMoved(t *testing.T) {
	dir := t.TempDir()
	window := updateWindow(time.Unix(0, 0), 24*time.Hour)
	reqs := []requirement{
		{Path: "example.com/a", Version: "v1.0.0"},
		{Path: "example.com/b", Version: "v2.0.0"},
		{Path: "example.com/c", Version: "v3.0.0"},
	}
	saveUpgrades(dir, window, reqs, map[string]state{
		"example.com/a": {Update: "v1.1.0"},
		"example.com/b": {Update: "v2.1.0"},
		"example.com/c": {Update: "v3.1.0"},
	})

	tests := []struct {
		name string
		// reqs is what the run now requires, and wantMissing which of those no entry
		// covers.
		reqs        []requirement
		wantMissing []requirement
		wantFound   []string
		wantWhy     string
	}{{
		name:      "nothing moved",
		reqs:      reqs,
		wantFound: []string{"example.com/a", "example.com/b", "example.com/c"},
	}, {
		// The case the whole change exists for.
		name: "one requirement moved",
		reqs: []requirement{
			{Path: "example.com/a", Version: "v1.0.0"},
			{Path: "example.com/b", Version: "v2.0.1"},
			{Path: "example.com/c", Version: "v3.0.0"},
		},
		wantMissing: []requirement{{Path: "example.com/b", Version: "v2.0.1"}},
		wantFound:   []string{"example.com/a", "example.com/c"},
		wantWhy:     "no recent answer for 1 of 3 requirements",
	}, {
		// A requirement added to go.mod is asked about; the others are not.
		name: "one requirement added",
		reqs: append(slices.Clone(reqs), requirement{Path: "example.com/d", Version: "v4.0.0"}),
		wantMissing: []requirement{
			{Path: "example.com/d", Version: "v4.0.0"},
		},
		wantFound: []string{"example.com/a", "example.com/b", "example.com/c"},
		wantWhy:   "no recent answer for 1 of 4 requirements",
	}, {
		// Dropping one asks about none: the entries for what remains still answer.
		name:      "one requirement dropped",
		reqs:      reqs[:2],
		wantFound: []string{"example.com/a", "example.com/b"},
	}, {
		// A tree sharing nothing with what was stored is the whole-miss case, which says
		// so rather than counting.
		name: "nothing in common",
		reqs: []requirement{
			{Path: "example.com/x", Version: "v1.0.0"},
			{Path: "example.com/y", Version: "v1.0.0"},
		},
		wantMissing: []requirement{
			{Path: "example.com/x", Version: "v1.0.0"},
			{Path: "example.com/y", Version: "v1.0.0"},
		},
		wantWhy: "no recent answer for these requirements",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found, missing, _, why := loadUpgrades(dir, window, tc.reqs)
			require.Equal(t, tc.wantMissing, missing)
			require.Equal(t, tc.wantWhy, why)
			require.Equal(t, tc.wantFound, slices.Sorted(maps.Keys(found)),
				"want every unmoved requirement answered from the cache")
		})
	}
}

// TestSaveUpgradesDeclinesToRecordAnUnknown checks that a module nothing was established about is
// not stored.
//
// Recording it would be worse than recording nothing. The entry would be reused for the rest of
// the window by runs that may well have a proxy again, so one unreachable moment would cost a day
// of modules reported as unchecked -- and a listing where every row carries a question mark is
// one nobody reads.
func TestSaveUpgradesDeclinesToRecordAnUnknown(t *testing.T) {
	dir := t.TempDir()
	window := updateWindow(time.Unix(0, 0), 24*time.Hour)
	reqs := []requirement{
		{Path: "example.com/known", Version: "v1.0.0"},
		{Path: "example.com/unknown", Version: "v1.0.0"},
		{Path: "example.com/absent", Version: "v1.0.0"},
	}
	saveUpgrades(dir, window, reqs, map[string]state{
		"example.com/known":   {Update: "v1.1.0"},
		"example.com/unknown": {Unknown: true},
		// example.com/absent is in neither map, as a module the toolchain reported an
		// error about is: parseUpdates leaves it out.
	})

	found, missing, _, _ := loadUpgrades(dir, window, reqs)
	require.Equal(t, []string{"example.com/known"}, slices.Sorted(maps.Keys(found)),
		"want only what was established recorded")
	require.Equal(t, reqs[1:], missing, "want an unknown module asked about again")
}

// TestStalenessReportsTheOldestPart checks that a listing assembled from several entries is aged
// by its oldest one.
//
// A listing is only as current as its least current part, so reporting the newest entry's age
// would describe the one thing that had just been refreshed and say nothing about the rest.
func TestStalenessReportsTheOldestPart(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		// at is what is folded in, in order.
		at []time.Time
		// want is the age expected, and wantKnown whether it is known at all.
		want      time.Duration
		wantKnown bool
	}{{
		// Nothing reused, so there is no answer to be old. Distinct from an unknown age,
		// though both render as "unknown": one has nothing to date, the other something
		// undatable.
		name: "nothing folded in",
	}, {
		name:      "one entry",
		at:        []time.Time{now.Add(-time.Hour)},
		want:      time.Hour,
		wantKnown: true,
	}, {
		name:      "the oldest of several wins",
		at:        []time.Time{now.Add(-time.Hour), now.Add(-3 * time.Hour), now.Add(-time.Minute)},
		want:      3 * time.Hour,
		wantKnown: true,
	}, {
		// Order must not decide it, since entries are read in whatever order the
		// requirements arrived.
		name:      "oldest first",
		at:        []time.Time{now.Add(-3 * time.Hour), now.Add(-time.Hour)},
		want:      3 * time.Hour,
		wantKnown: true,
	}, {
		// An undatable entry is not evidence of freshness, so it leaves the whole age
		// unknown rather than being skipped in favour of the dated ones.
		name: "one entry of unknown date",
		at:   []time.Time{now.Add(-time.Hour), {}},
	}, {
		// A file dated in the future reads as current rather than as a negative age,
		// which would render as "-1h0m0s" and read as a release yet to happen.
		name:      "an entry dated ahead",
		at:        []time.Time{now.Add(time.Hour)},
		want:      0,
		wantKnown: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var st staleness
			for _, at := range tc.at {
				st.add(at)
			}
			age := st.age()
			require.Equal(t, tc.wantKnown, age.known)
			if !tc.wantKnown {
				return
			}
			require.InDelta(t, tc.want, age.of, float64(time.Minute))
		})
	}
}

// TestStalenessMergesTwoSources checks that folding one listing's age into another keeps the
// oldest, which is what the offline fallback needs: it adds entries from a second read to a
// listing already assembled from a first.
func TestStalenessMergesTwoSources(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		// a and b are the two listings, given as the moments folded into each.
		a, b      []time.Time
		want      time.Duration
		wantKnown bool
	}{{
		name:      "the older of the two wins",
		a:         []time.Time{now.Add(-time.Hour)},
		b:         []time.Time{now.Add(-5 * time.Hour)},
		want:      5 * time.Hour,
		wantKnown: true,
	}, {
		name:      "and does so whichever side it is on",
		a:         []time.Time{now.Add(-5 * time.Hour)},
		b:         []time.Time{now.Add(-time.Hour)},
		want:      5 * time.Hour,
		wantKnown: true,
	}, {
		// An empty listing contributes nothing rather than resetting the age, which is
		// the case where the fallback found no entry at all.
		name:      "merging an empty listing changes nothing",
		a:         []time.Time{now.Add(-time.Hour)},
		want:      time.Hour,
		wantKnown: true,
	}, {
		name:      "merging into an empty listing takes its age",
		b:         []time.Time{now.Add(-time.Hour)},
		want:      time.Hour,
		wantKnown: true,
	}, {
		// Unknown on either side leaves the whole thing unknown.
		name: "an undatable entry on the far side",
		a:    []time.Time{now.Add(-time.Hour)},
		b:    []time.Time{{}},
	}}

	fold := func(at []time.Time) staleness {
		var st staleness
		for _, t := range at {
			st.add(t)
		}
		return st
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			age := fold(tc.a).merge(fold(tc.b)).age()
			require.Equal(t, tc.wantKnown, age.known)
			if !tc.wantKnown {
				return
			}
			require.InDelta(t, tc.want, age.of, float64(time.Minute))
		})
	}
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
	at := filepath.Join(dir, updateCacheDir, moduleKey(reqs[0], window)+".json")
	backdated := time.Now().Add(-90 * time.Minute)
	require.NoError(t, os.Chtimes(at, backdated, backdated))

	_, missing, st, _ := loadUpgrades(dir, window, reqs)
	require.Empty(t, missing)
	age := st.age()
	require.True(t, age.known, "want the age of the entry")
	// A window either side of the hour and a half, so a slow test does not fail on timing.
	require.InDelta(t, 90*time.Minute, age.of, float64(time.Minute),
		"want the age measured from when the entry was written")
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
			_, missing, _, why := loadUpgrades(tc.cache, tc.window, reqs)
			require.Equal(t, reqs, missing, "want everything left to ask about")
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
