package app

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// memo holds one answer per distinct question asked during a run.
//
// The questions are reads of the module graph, the import graph and the vulnerability
// database, each of which the toolchain redoes from scratch on every invocation. A run
// is one shot, so nothing it reads can change underneath it: an answer is good for as
// long as the process lives, and a second asking is work already done.
//
// Callers ask concurrently -- workspace members are read at once, and each member is
// swept across its configurations at once -- so an entry is a memoized closure rather
// than a value. Whoever asks first computes; everyone else waits on that same call and
// takes its result. Two goroutines asking together therefore run one go command, not
// two, which is what a plain map of results would not give: it would dedupe the entry
// and still let both callers compute.
type memo struct {
	// entries maps MemoArgs to a func() (any, error) yielding the answer. sync.Map
	// rather than a guarded map because the keys are written once and read many
	// times, and because LoadOrStore is the single operation the discipline needs.
	entries sync.Map
	// hits and misses count what was reused and what had to be gathered.
	//
	// Kept because whether this cache does anything is a question about the call
	// paths rather than about recall: a gatherer wired to bypass it, or keyed on
	// something that differs every time, still returns right answers and reuses
	// nothing. A test can see the difference here; it cannot see it in the output.
	hits   atomic.Int64
	misses atomic.Int64
}

// reuse reports how much was served from memory against how much was gathered.
func (m *memo) reuse() (hits, misses int64) {
	if m == nil {
		return 0, 0
	}
	return m.hits.Load(), m.misses.Load()
}

// MemoArgs is the arguments a gatherer is called with, and so the key its answer is
// remembered by. One type per gatherer, holding exactly what decides the result.
//
// The call is the key: two askings share an answer when they would pass the same
// arguments to the same function, which is the only condition under which reusing one
// is correct. Comparable because that is what a map key must be -- a gatherer whose
// arguments cannot be compared cannot be memoized, and the constraint says so where it
// is introduced rather than panicking at the first Store. It is also why a set of build
// tags is carried as the argument the toolchain is given rather than as the slice it
// came from.
//
// Distinct types never collide even with identical fields, since comparing interface
// values compares the dynamic type before the value.
type MemoArgs interface{ comparable }

// MemoFunc gathers the answer to one asking. It takes its arguments rather than
// closing over them, so what it reads and what its answer is filed under cannot
// disagree.
type MemoFunc[K MemoArgs, T any] func(K) (T, error)

// The questions asked during a run, one type per gatherer.
type (
	// graphArgs asks for the whole module graph below a directory.
	graphArgs struct{ dir string }
	// depsArgs asks which modules import which, under one configuration.
	depsArgs struct {
		dir  string
		tags string
	}
	// vulnArgs asks which advisories affect a directory under one configuration.
	// Whether the scan may be reused belongs in the key: the two answers are read
	// from different places and a run can want either.
	vulnArgs struct {
		dir     string
		tags    string
		caching bool
	}
)

// moduleGraph returns every module in the build list below dir, reading it once per
// directory however many times it is asked for.
func (app *AppEnv) moduleGraph(ctx context.Context, dir string) ([]requirement, error) {
	return recall(app.answers, graphArgs{dir: dir},
		func(args graphArgs) ([]requirement, error) {
			return graph(ctx, args.dir)
		})
}

// importGraph returns which modules import which under one configuration, reading it
// once per directory and configuration.
//
// The tags are part of the question rather than incidental to it: a configuration
// decides which files compile and so which modules the build reaches, which is what the
// sweep exists to vary.
func (app *AppEnv) importGraph(ctx context.Context, dir string, f tagFilter) (dependents, error) {
	return recall(app.answers, depsArgs{dir: dir, tags: f.String()},
		func(args depsArgs) (dependents, error) {
			return reverseDeps(ctx, dir, f)
		})
}

// advisories returns the vulnerabilities affecting dir under one configuration, scanning
// once per directory and configuration.
func (app *AppEnv) advisories(ctx context.Context, dir string, f tagFilter) (vulnerabilities, error) {
	return recall(app.answers, vulnArgs{dir: dir, tags: f.String(), caching: app.caching()},
		func(args vulnArgs) (vulnerabilities, error) {
			return scanVulnerabilities(ctx, dir, f, args.caching)
		})
}

// recall returns the answer to args, computing it with gather the first time they are
// asked and returning that same answer to every later caller.
//
// An error is remembered along with the answer. A failed go command in a one-shot run
// fails the same way on a second asking, and reporting one failure twice would describe
// one fault as two.
//
// A nil memo remembers nothing and gathers every time. Correctness does not depend on
// the cache -- it saves repeated work and decides nothing -- so a caller that never set
// one up gets the right answer at the old price rather than a panic.
func recall[K MemoArgs, T any](m *memo, args K, gather MemoFunc[K, T]) (T, error) {
	if m == nil {
		return gather(args)
	}
	// The closure is built before it is known whether it is wanted, which costs an
	// allocation and no work: LoadOrStore returns the entry already there if one is,
	// and nothing has run until someone calls it.
	entry, loaded := m.entries.LoadOrStore(args, sync.OnceValues(func() (any, error) {
		return gather(args)
	}))
	// Counted on the entry rather than on the call, since that is the question being
	// asked: two callers arriving together are one gather and one reuse, which is what
	// the closure is for.
	if loaded {
		m.hits.Add(1)
	} else {
		m.misses.Add(1)
	}
	call, ok := entry.(func() (any, error))
	if !ok {
		// Unreachable: every entry is stored here. Reported rather than asserted so a
		// future caller storing something else fails where it can be read, instead of
		// panicking inside a concurrent sweep.
		var zero T
		return zero, fmt.Errorf("cache holds %T for %#v, which is not an answer", entry, args)
	}
	v, err := call()
	if err != nil {
		var zero T
		return zero, err
	}
	answer, ok := v.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("cache holds %T for %#v, want %T", v, args, zero)
	}
	return answer, nil
}
