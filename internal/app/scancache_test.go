package app

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// write puts a file in a directory, creating any parents.
func writeAt(t *testing.T, dir, name, body string) {
	t.Helper()
	at := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(at, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// module builds a small module tree and returns its directory.
func moduleAt(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeAt(t, dir, "go.mod", "module example.com/m\n\ngo 1.24\n")
	writeAt(t, dir, "go.sum", "example.com/dep v1.0.0 h1:abc=\n")
	writeAt(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	writeAt(t, dir, "inner/lib.go", "package inner\n")
	return dir
}

// TestScanKeyNoticesALengthMismatch checks that a file whose contents do not match the length
// written before them is an error rather than a key.
//
// The length is hashed ahead of the payload so the digest commits to where the payload ends.
// The two agreeing is therefore part of the contract: a file that grew or shrank between
// being sized and being read would produce a key describing a file that never existed, which
// no later run can reproduce -- so the scan would never be reused and nothing would say why.
//
// A named pipe is the deterministic way to force the disagreement: it stats as empty and then
// yields bytes.
func TestScanKeyNoticesALengthMismatch(t *testing.T) {
	dir := moduleAt(t)
	at := filepath.Join(dir, "pipe.go")
	if err := syscall.Mkfifo(at, 0o600); err != nil {
		t.Skipf("cannot create a named pipe here: %v", err)
	}

	// The pipe blocks until a writer arrives, so one has to be waiting.
	go func() {
		w, err := os.OpenFile(at, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		_, _ = w.WriteString("package main\n")
		_ = w.Close()
	}()

	_, err := scanKey(dir, nil, "etag", "go1.24")
	if err == nil {
		t.Fatal("a file yielding more bytes than its length produced a key rather than an error")
	}
	if !strings.Contains(err.Error(), "changed while being read") {
		t.Errorf("error = %v, want it to name the disagreement", err)
	}
}

// TestScanKeyCommitsToTagBoundaries checks a tag cannot impersonate a field separator.
//
// The fields are written as lines, so an unquoted value holding a newline could stand in for
// two fields, and two different sets of build tags could hash alike.
func TestScanKeyCommitsToTagBoundaries(t *testing.T) {
	dir := moduleAt(t)

	honest, err := scanKey(dir, []string{"one", "two"}, "etag", "go1.24")
	if err != nil {
		t.Fatal(err)
	}
	// Written unquoted, this would emit the same two "tag=" lines as the pair above.
	forged, err := scanKey(dir, []string{"one\ntag=two"}, "etag", "go1.24")
	if err != nil {
		t.Fatal(err)
	}
	if honest == forged {
		t.Error("a tag holding a newline hashes as two tags, so distinct configurations share a key")
	}
}

// TestScanKeyCoversTheSources checks that the key changes when anything the scan reads
// changes, and not when something it ignores does.
//
// govulncheck answers a question about reachability, which is decided by the source rather
// than by the requirements: adding a call to a package of an already-required module changes
// the answer while leaving go.mod and go.sum byte-identical. A key on the requirements alone
// would serve "reachable" after the call was deleted.
func TestScanKeyCoversTheSources(t *testing.T) {
	dir := moduleAt(t)
	base, err := scanKey(dir, nil, "etag", "go1.24.0")
	if err != nil {
		t.Fatalf("scanKey: %v", err)
	}

	for _, tc := range []struct {
		name   string
		change func()
		same   bool
	}{{
		// The requirements, which is what a naive key would cover.
		name:   "go.mod",
		change: func() { writeAt(t, dir, "go.mod", "module example.com/m\n\ngo 1.25\n") },
	}, {
		name:   "go.sum",
		change: func() { writeAt(t, dir, "go.sum", "example.com/dep v1.1.0 h1:xyz=\n") },
	}, {
		// The case the requirements miss: a call added or removed within a module
		// already required.
		name:   "a source file",
		change: func() { writeAt(t, dir, "main.go", "package main\n\nfunc main() { println(1) }\n") },
	}, {
		name:   "a source file in a subdirectory",
		change: func() { writeAt(t, dir, "inner/lib.go", "package inner\n\nvar X = 1\n") },
	}, {
		// A new file the scan would read.
		name:   "a new source file",
		change: func() { writeAt(t, dir, "other.go", "package main\n") },
	}, {
		// Build artefacts and vendored trees are not this project's source, and the
		// same rule that keeps them out of the tag search keeps them out of the key.
		name:   "a vendored file",
		change: func() { writeAt(t, dir, "vendor/x/y.go", "package y\n") },
		same:   true,
	}, {
		name:   "testdata",
		change: func() { writeAt(t, dir, "testdata/broken.go", "package nope\n") },
		same:   true,
	}, {
		name:   "a dotfile directory",
		change: func() { writeAt(t, dir, ".cache/x.go", "package x\n") },
		same:   true,
	}, {
		// Not Go source at all.
		name:   "a readme",
		change: func() { writeAt(t, dir, "readme.md", "# hello\n") },
		same:   true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			tc.change()
			got, err := scanKey(dir, nil, "etag", "go1.24.0")
			if err != nil {
				t.Fatalf("scanKey: %v", err)
			}
			if tc.same && got != base {
				t.Errorf("key changed for %s, want it ignored", tc.name)
			}
			if !tc.same && got == base {
				t.Errorf("key unchanged for %s, want it covered", tc.name)
			}
			base = got
		})
	}
}

// TestScanKeyCoversWhatElseDecidesTheAnswer checks the inputs that are not files.
//
// A build tag decides which files compile, the database decides which advisories exist, and
// the toolchain decides what the standard library contains. A key missing any of them would
// answer a different question than the one asked.
func TestScanKeyCoversWhatElseDecidesTheAnswer(t *testing.T) {
	dir := moduleAt(t)
	base, err := scanKey(dir, nil, "etag", "go1.24.0")
	if err != nil {
		t.Fatalf("scanKey: %v", err)
	}

	for _, tc := range []struct {
		name      string
		tags      []string
		etag      string
		toolchain string
	}{
		{name: "build tags", tags: []string{"-tags=integration"}, etag: "etag", toolchain: "go1.24.0"},
		{name: "the database", tags: nil, etag: "another", toolchain: "go1.24.0"},
		{name: "the toolchain", tags: nil, etag: "etag", toolchain: "go1.25.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scanKey(dir, tc.tags, tc.etag, tc.toolchain)
			if err != nil {
				t.Fatalf("scanKey: %v", err)
			}
			if got == base {
				t.Errorf("key unchanged for %s, want it covered", tc.name)
			}
		})
	}
}

// TestScanKeyIsStable checks that the same tree yields the same key, whatever order the walk
// happens to return files in.
//
// The files are sorted before hashing, since a filesystem gives no ordering guarantee and a
// key that varied by directory order would miss every cache hit.
func TestScanKeyIsStable(t *testing.T) {
	dir := moduleAt(t)
	// Several files whose walk order is not guaranteed to be stable across platforms.
	for _, name := range []string{"a.go", "z.go", "m.go", "sub/b.go", "sub/y.go"} {
		writeAt(t, dir, name, "package p\n")
	}
	first, err := scanKey(dir, []string{"-tags=x"}, "etag", "go1.24.0")
	if err != nil {
		t.Fatalf("scanKey: %v", err)
	}
	for range 5 {
		got, err := scanKey(dir, []string{"-tags=x"}, "etag", "go1.24.0")
		if err != nil {
			t.Fatalf("scanKey: %v", err)
		}
		if got != first {
			t.Fatalf("scanKey() = %q, want %q on every call", got, first)
		}
	}
	// And it is a usable directory name rather than raw bytes.
	if filepath.Base(first) != first || first == "" {
		t.Errorf("scanKey() = %q, want a single path element", first)
	}
}

// TestScanCacheRoundTrips checks that a scan result survives being stored and read back.
func TestScanCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := vulnerabilities{
		"golang.org/x/text": []vulnerability{{
			ID:      "GO-2026-5970",
			Aliases: []string{"CVE-2026-56852"},
			FixedIn: "v0.39.0",
			URL:     "https://pkg.go.dev/vuln/GO-2026-5970",
			Called:  true,
		}},
		"example.com/quiet": []vulnerability{},
	}

	if err := storeScan(dir, "abc123", want); err != nil {
		t.Fatalf("storeScan: %v", err)
	}
	got, ok := loadScan(dir, "abc123")
	if !ok {
		t.Fatal("loadScan found nothing, want the stored result")
	}
	if len(got) != len(want) {
		t.Fatalf("loadScan() = %v, want %v", got, want)
	}
	// Called is what decides whether a policy fails or warns, so it has to survive.
	found := got["golang.org/x/text"]
	if len(found) != 1 || !found[0].Called {
		t.Errorf("got %+v, want the reachability preserved", found)
	}
	if found[0].ID != "GO-2026-5970" || found[0].FixedIn != "v0.39.0" {
		t.Errorf("got %+v, want the advisory preserved", found[0])
	}

	// A different key is a different question, so it misses.
	if _, ok := loadScan(dir, "different"); ok {
		t.Error("loadScan hit on a different key, want a miss")
	}
	// So does an empty cache.
	if _, ok := loadScan(t.TempDir(), "abc123"); ok {
		t.Error("loadScan hit on an empty cache, want a miss")
	}
}

// TestScanCacheStoresAnEmptyResult checks that "nothing found" is cached too.
//
// A clean scan is the common case and the most expensive thing to repeat, so it has to be
// distinguishable from a miss -- otherwise every clean project pays the full cost every run.
func TestScanCacheStoresAnEmptyResult(t *testing.T) {
	dir := t.TempDir()
	if err := storeScan(dir, "clean", vulnerabilities{}); err != nil {
		t.Fatalf("storeScan: %v", err)
	}
	got, ok := loadScan(dir, "clean")
	if !ok {
		t.Fatal("loadScan found nothing, want a stored empty result")
	}
	if len(got) != 0 {
		t.Errorf("loadScan() = %v, want an empty result", got)
	}
}

// TestScanCacheIgnoresRubbish checks that an unreadable entry reads as a miss.
//
// A truncated or hand-edited file should cost a rescan, not a crash or a wrong answer.
func TestScanCacheIgnoresRubbish(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, scanCacheDir), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAt(t, dir, filepath.Join(scanCacheDir, "bad.json"), "{not json")
	if _, ok := loadScan(dir, "bad"); ok {
		t.Error("loadScan hit on an unreadable entry, want a miss")
	}
}

// TestCachingIsOffWhenTiming checks that asking what a phase costs measures the work rather
// than the cache.
//
// A warm run skips the scan entirely, so timing one reports what reading a file costs -- which
// is not the question anyone asks --timing to answer. So timing implies no cache, and says so
// rather than quietly producing a misleading number.
func TestCachingIsOffWhenTiming(t *testing.T) {
	for _, tc := range []struct {
		name  string
		app   AppEnv
		using bool
	}{
		// Nothing said, so the cache is used: it is what makes a second run quick.
		{name: "by default", app: AppEnv{}, using: true},
		{name: "asked for", app: AppEnv{Cache: new(true)}, using: true},
		// Declined outright.
		{name: "declined", app: AppEnv{Cache: new(false)}, using: false},
		// Timing measures the work, so the cache goes.
		{name: "timing", app: AppEnv{Timing: true}, using: false},
		// Unless the caller insisted, which is their business: they may be timing the
		// cache itself.
		{name: "timing with the cache asked for", app: AppEnv{Timing: true, Cache: new(true)}, using: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.caching(); got != tc.using {
				t.Errorf("caching() = %v, want %v", got, tc.using)
			}
		})
	}
}
