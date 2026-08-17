package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRecallGathersOncePerDistinctArgs checks that an answer is computed once and reused,
// and that two askings only share an answer when they would have asked the same thing.
//
// Both halves matter and they pull against each other. Reusing too eagerly is the worse
// fault: the tag sweep asks the same directory about seven configurations, and collapsing
// those would report one configuration's reach as the whole build's.
func TestRecallGathersOncePerDistinctArgs(t *testing.T) {
	tests := []struct {
		name string
		args []depsArgs
		// want is how many times the gatherer should run across every asking.
		want int32
	}{
		{
			name: "the same asking twice runs once",
			args: []depsArgs{{dir: "/a"}, {dir: "/a"}},
			want: 1,
		},
		{
			name: "different directories are different questions",
			args: []depsArgs{{dir: "/a"}, {dir: "/b"}},
			want: 2,
		},
		{
			// The case the sweep depends on: one directory, one pass per configuration.
			name: "the same directory under different tags is not one question",
			args: []depsArgs{
				{dir: "/a", tags: ""},
				{dir: "/a", tags: "integration"},
				{dir: "/a", tags: "integration,linux"},
			},
			want: 3,
		},
		{
			name: "and repeats within those still collapse",
			args: []depsArgs{
				{dir: "/a", tags: "integration"},
				{dir: "/a", tags: "integration"},
				{dir: "/a", tags: ""},
			},
			want: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &memo{}
			var calls atomic.Int32
			gather := func(args depsArgs) (string, error) {
				calls.Add(1)
				return args.dir + "|" + args.tags, nil
			}
			for _, args := range tc.args {
				got, err := recall(m, args, gather)
				require.NoError(t, err)
				require.Equal(t, args.dir+"|"+args.tags, got,
					"want the answer to the question asked, not another entry's")
			}
			require.Equal(t, tc.want, calls.Load())
		})
	}
}

// sameShapeArgs is a key type indistinguishable from graphArgs by anything but its type:
// one string field, so the two render identically however they are formatted.
//
// It exists because graphArgs and depsArgs do NOT collide when flattened -- depsArgs has a
// second field, so "%v" renders "{/a }" against graphArgs' "{/a}" and they differ by shape
// rather than by type. A test using those two passes even with the keys stringified, which
// says nothing about what separates them.
type sameShapeArgs struct{ dir string }

// TestRecallKeepsKindsApart checks that two gatherers asking about the same directory do
// not share an entry, even when their arguments are identical in everything but type.
//
// This rests on sync.Map comparing the dynamic type before the value. Worth pinning
// because the failure is silent and remote: flatten these keys to strings and one
// gatherer is served the other's answer, which surfaces as a type assertion failure
// wherever the answer is finally used rather than here.
func TestRecallKeepsKindsApart(t *testing.T) {
	m := &memo{}

	graph, err := recall(m, graphArgs{dir: "/a"}, func(graphArgs) (string, error) {
		return "module graph", nil
	})
	require.NoError(t, err)
	require.Equal(t, "module graph", graph)

	other, err := recall(m, sameShapeArgs{dir: "/a"}, func(sameShapeArgs) (string, error) {
		return "something else", nil
	})
	require.NoError(t, err)
	require.Equal(t, "something else", other,
		"want each gatherer its own entry, not whichever asked first")
}

// TestRecallSingleFlights checks that callers arriving together run the gatherer once
// between them and all take its result.
//
// This is why an entry is a memoized closure and not a value. A map of results would
// dedupe the entry and still let every goroutine compute: the tool reads workspace
// members at once and sweeps each across its configurations at once, so simultaneous
// arrival is the ordinary case rather than a race to be tolerated.
func TestRecallSingleFlights(t *testing.T) {
	const askers = 32

	var (
		m     = &memo{}
		calls atomic.Int32
		// Held until every caller has arrived, so they contend rather than
		// happening to run in turn.
		release = make(chan struct{})
		ready   sync.WaitGroup
		done    sync.WaitGroup
	)
	ready.Add(askers)
	done.Add(askers)

	answers := make([]string, askers)
	errs := make([]error, askers)
	for i := range askers {
		go func() {
			defer done.Done()
			ready.Done()
			<-release
			answers[i], errs[i] = recall(m, depsArgs{dir: "/a"},
				func(args depsArgs) (string, error) {
					calls.Add(1)
					return "gathered once", nil
				})
		}()
	}
	ready.Wait()
	close(release)
	done.Wait()

	require.Equal(t, int32(1), calls.Load(),
		"want one gather across every caller, not one per caller")
	for i := range askers {
		require.NoError(t, errs[i])
		require.Equal(t, "gathered once", answers[i])
	}
}

// TestRecallRemembersAFailure checks that a failed gather is not retried.
//
// A go command that failed in a one-shot run fails the same way on a second asking, and
// returning the error to every caller means one fault is reported once rather than once
// per configuration that happened to ask.
func TestRecallRemembersAFailure(t *testing.T) {
	m := &memo{}
	var calls atomic.Int32
	want := errors.New("go list: exit status 1")
	gather := func(depsArgs) (string, error) {
		calls.Add(1)
		return "", want
	}

	for range 3 {
		got, err := recall(m, depsArgs{dir: "/a"}, gather)
		require.ErrorIs(t, err, want)
		require.Empty(t, got, "want no answer alongside an error")
	}
	require.Equal(t, int32(1), calls.Load(), "want the failure remembered, not re-run")
}

// TestRecallReportsAMismatchedAnswer checks that asking for a type the entry does not hold
// is reported rather than panicking.
//
// Unreachable through the gatherers, which each own their key type. It exists because the
// alternative to reporting is a panic inside a concurrent sweep, where the stack says
// little about which caller was wrong.
func TestRecallReportsAMismatchedAnswer(t *testing.T) {
	m := &memo{}

	first, err := recall(m, depsArgs{dir: "/a"}, func(depsArgs) (string, error) {
		return "a string", nil
	})
	require.NoError(t, err)
	require.Equal(t, "a string", first)

	second, err := recall(m, depsArgs{dir: "/a"}, func(depsArgs) (int, error) {
		return 42, nil
	})
	require.Error(t, err)
	require.Zero(t, second)
	require.Contains(t, err.Error(), "want int")
}

// TestGatherersRouteThroughTheMemo checks that the real gatherers reuse an answer, rather
// than recall merely working when called directly.
//
// This is the property the unit tests above cannot see. recall can be correct while every
// caller bypasses it, or keys on something that differs on each asking -- the output stays
// right and nothing is ever reused, which is exactly the failure worth catching. So the
// assertion is on the memo's own counters, reached through the same methods runDir and
// runWorkspace call.
//
// Each question is asked against a directory holding no module, so the underlying go
// command fails immediately: this needs the bookkeeping to be exercised, not the toolchain.
// A remembered failure is still a remembered answer, which is what makes that sound.
func TestGatherersRouteThroughTheMemo(t *testing.T) {
	ctx := context.Background()
	// Not a module, so every gatherer fails fast and none of them shell out to a real
	// build. The error is beside the point; where the answer is filed is the point.
	dir := t.TempDir()

	tests := []struct {
		name string
		ask  func(app *AppEnv) error
	}{
		{
			name: "the module graph",
			ask: func(app *AppEnv) error {
				_, err := app.moduleGraph(ctx, dir)
				return err
			},
		},
		{
			name: "the import graph",
			ask: func(app *AppEnv) error {
				_, err := app.importGraph(ctx, dir, tagFilter{})
				return err
			},
		},
		{
			name: "the advisories",
			ask: func(app *AppEnv) error {
				_, err := app.advisories(ctx, dir, tagFilter{})
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppEnv{answers: &memo{}}

			// The first asking has nothing to reuse.
			_ = tc.ask(app)
			hits, misses := app.answers.reuse()
			require.Equal(t, int64(0), hits)
			require.Equal(t, int64(1), misses, "want the first asking gathered")

			// The second is the same question, so it must be served rather than re-run.
			_ = tc.ask(app)
			hits, misses = app.answers.reuse()
			require.Equal(t, int64(1), hits, "want the second asking reused, not gathered again")
			require.Equal(t, int64(1), misses, "want no second gather")
		})
	}
}

// TestGatherersKeepConfigurationsApart checks that the sweep's passes stay separate
// questions once routed through the memo.
//
// The tags reach the key through tagFilter.String(), so this is what stands between a
// memoized sweep and a collapsed one: seven configurations served one configuration's
// answer would report a subset of the build as the whole of it, and every row would still
// look plausible.
func TestGatherersKeepConfigurationsApart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	app := &AppEnv{answers: &memo{}}

	// The plain build, then two tagged configurations: three questions, not one.
	for _, f := range []tagFilter{
		{},
		{tags: []string{"integration"}},
		{tags: []string{"integration", "multinode"}},
	} {
		_, _ = app.importGraph(ctx, dir, f)
	}
	hits, misses := app.answers.reuse()
	require.Equal(t, int64(0), hits, "want no configuration served another's answer")
	require.Equal(t, int64(3), misses, "want each configuration asked in its own right")

	// Asking the middle one again is a repeat, and only then is anything reused.
	_, _ = app.importGraph(ctx, dir, tagFilter{tags: []string{"integration"}})
	hits, misses = app.answers.reuse()
	require.Equal(t, int64(1), hits)
	require.Equal(t, int64(3), misses)
}

// writeAged writes a cache entry in sub and backdates it, returning its path.
func writeAged(t *testing.T, dir, sub, name string, age time.Duration) string {
	t.Helper()
	at := filepath.Join(dir, sub)
	require.NoError(t, os.MkdirAll(at, 0o755))
	name = filepath.Join(at, name)
	require.NoError(t, os.WriteFile(name, []byte(`{}`), 0o600))
	if age > 0 {
		was := time.Now().Add(-age)
		require.NoError(t, os.Chtimes(name, was, was))
	}
	return name
}

// TestPruneDropsOnlyEntriesPastTheirLife checks that the sweep decides by age, and that it
// decides per entry rather than per directory.
//
// A sweep that took the whole of a subdirectory would empty the cache of a project in daily
// use, since the entries a run reuses sit beside the ones it has finished with.
func TestPruneDropsOnlyEntriesPastTheirLife(t *testing.T) {
	tests := []struct {
		name string
		sub  string
	}{
		{name: "upgrade answers", sub: updateCacheDir},
		{name: "release histories", sub: releaseCacheDir},
		{name: "scan results", sub: scanCacheDir},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stale := writeAged(t, dir, tc.sub, "stale.json", 8*24*time.Hour)
			fresh := writeAged(t, dir, tc.sub, "fresh.json", time.Hour)

			require.Equal(t, int64(1), prune(context.Background(), dir, DefaultCacheLife),
				"want the one entry past its life dropped")
			require.NoFileExists(t, stale)
			require.FileExists(t, fresh, "want an entry still in use kept")
		})
	}
}

// TestPruneLeavesTheVulnerabilityDatabase checks that the sweep does not age out the database.
//
// It is one shared copy revalidated against its etag rather than an entry per key, so an old
// modification time means it is still current. Sweeping by age would discard the largest and
// most expensive thing in the cache precisely when it needed no refetching.
func TestPruneLeavesTheVulnerabilityDatabase(t *testing.T) {
	dir := t.TempDir()
	old := 30 * 24 * time.Hour
	etag := writeAged(t, dir, ".", etagFile, old)
	blob := writeAged(t, dir, "deadbeef", "osv.json", old)

	require.Equal(t, int64(0), prune(context.Background(), dir, DefaultCacheLife))
	require.FileExists(t, etag)
	require.FileExists(t, blob, "want the database kept however old it is")
}

// TestPruneStopsWhenCancelled checks that a cancelled run stops the sweep rather than leaving
// it unlinking files behind a process that has been asked to stop.
func TestPruneStopsWhenCancelled(t *testing.T) {
	dir := t.TempDir()
	stale := writeAged(t, dir, updateCacheDir, "stale.json", 8*24*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, int64(0), prune(ctx, dir, DefaultCacheLife))
	require.FileExists(t, stale, "want nothing dropped once the run is cancelled")
}

// TestPruneDeclinesWithoutACacheOrALife checks the two ways of saying there is nothing to do.
//
// An empty directory means the cache could not be located, and a zero life means no entry is
// old enough to drop. Reading either as "sweep everything" would empty a cache that the run had
// no location for or no cutoff to apply.
func TestPruneDeclinesWithoutACacheOrALife(t *testing.T) {
	tests := []struct {
		name string
		dir  bool
		life time.Duration
	}{
		{name: "no cache located", dir: false, life: DefaultCacheLife},
		{name: "no life to measure against", dir: true, life: 0},
		{name: "a negative life", dir: true, life: -time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stale := writeAged(t, dir, updateCacheDir, "stale.json", 90*24*time.Hour)
			at := ""
			if tc.dir {
				at = dir
			}
			require.Equal(t, int64(0), prune(context.Background(), at, tc.life))
			require.FileExists(t, stale)
		})
	}
}

// TestPruneKeepsDirectories checks that only the flat per-key files are swept.
//
// A directory inside a swept subdirectory was not written by this package, and removing a tree
// on the strength of its modification time is a larger claim than the sweep can make.
func TestPruneKeepsDirectories(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, updateCacheDir, "nested")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	was := time.Now().Add(-90 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(nested, was, was))

	require.Equal(t, int64(0), prune(context.Background(), dir, DefaultCacheLife))
	require.DirExists(t, nested)
}

// TestReusingAScanMarksItAsUsed checks that reading an entry keeps it, rather than only writing
// one doing so.
//
// A scan is keyed on the project's own sources, so an unedited tree hits the same entry for as
// long as it stands still and storeScan never runs again. Deciding by modification time alone
// would age out the most expensive entry in the cache while it was answering every run, so this
// goes through loadScan rather than calling touch: the wiring is the claim.
func TestReusingAScanMarksItAsUsed(t *testing.T) {
	dir := t.TempDir()
	key := "scan"
	at := writeAged(t, dir, scanCacheDir, key+".json", 8*24*time.Hour)

	found, ok := loadScan(dir, key)
	require.True(t, ok, "want the aged entry still readable")
	require.NotNil(t, found)

	require.Equal(t, int64(0), prune(context.Background(), dir, DefaultCacheLife),
		"want a reused entry kept")
	require.FileExists(t, at)
}

// TestReusingAnUpgradeAnswerLeavesItsAge checks that reading an answer does not restamp it.
//
// The opposite of a scan, and deliberately so: loadAnswer returns the modification time as the
// age of the answer, which is what a listing reports. Touching it on a hit would make an answer
// gathered yesterday claim to be current, which is the one reading that makes a stale listing
// look fresh.
func TestReusingAnUpgradeAnswerLeavesItsAge(t *testing.T) {
	dir := t.TempDir()
	key := "answer"
	at := writeAged(t, dir, updateCacheDir, key+".json", 36*time.Hour)
	before, err := os.Stat(at)
	require.NoError(t, err)

	_, written, ok := loadAnswer(dir, key)
	require.True(t, ok)
	require.WithinDuration(t, before.ModTime(), written,
		time.Second, "want the age reported as gathered, not as read")

	after, err := os.Stat(at)
	require.NoError(t, err)
	require.Equal(t, before.ModTime(), after.ModTime(), "want reading to leave the age alone")
}
