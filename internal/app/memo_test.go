package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

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
