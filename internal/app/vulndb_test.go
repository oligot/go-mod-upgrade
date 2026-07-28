package app

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEtagName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"quoted", `"08d87061c352e6833bdce66670b1febe"`, "08d87061c352e6833bdce66670b1febe"},
		{"weak validator", `W/"abc123"`, "abc123"},
		{"unquoted", "abc123", "abc123"},
		{"surrounding space", `  "abc123"  `, "abc123"},
		// The value only has to tell one copy from another, so anything that
		// would make it more than a single path element is dropped.
		{"path separator", `"ab/../cd"`, "abcd"},
		{"multipart", `"abc-123"`, "abc-123"},
		{"underscore kept", `"abc_123"`, "abc_123"},
		{"empty", `""`, ""},
		{"only separators", `"///"`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := etagName(c.in); got != c.want {
				t.Errorf("etagName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// zipWith builds an archive holding the named entries.
func zipWith(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	return buf.Bytes()
}

func TestUnpack(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("closing the root: %v", err)
		}
	})

	archive := zipWith(t, map[string]string{
		"index/db.json":        `{"modified":"2026-07-27T16:28:49Z"}`,
		"ID/GO-2026-5970.json": `{"id":"GO-2026-5970"}`,
	})
	if err := unpack(root, "etag1", archive); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	for _, name := range []string{
		filepath.Join("etag1", "index", "db.json"),
		filepath.Join("etag1", "ID", "GO-2026-5970.json"),
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
}

// TestUnpackConfinesEntries checks that an archive cannot write outside the
// cache, whichever of the two defences acts first: names are cleaned before
// use, and the root refuses anything that still resolves outside itself.
func TestUnpackConfinesEntries(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("closing the root: %v", err)
		}
	})

	archive := zipWith(t, map[string]string{
		"../escaped.json":       `{}`,
		"a/../../escaped2.json": `{}`,
		"index/db.json":         `{}`,
	})
	// Whether an escaping entry is refused or flattened does not matter, only
	// that nothing lands outside.
	_ = unpack(root, "etag1", archive)

	parent := filepath.Dir(dir)
	for _, name := range []string{"escaped.json", "escaped2.json"} {
		if _, err := os.Stat(filepath.Join(parent, name)); err == nil {
			t.Errorf("%s escaped the cache", name)
		}
	}
	// Everything written must be inside the directory named for this version.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the cache: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "etag1" {
			t.Errorf("unexpected %q beside the database directory", e.Name())
		}
	}
}

// TestRootRejectsEscapingNames records the guarantee unpack relies on, so that
// replacing the root with plain file operations is visibly a change in
// behaviour rather than a silent one.
func TestRootRejectsEscapingNames(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "cache")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("creating the cache: %v", err)
	}
	root, err := os.OpenRoot(sub)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("closing the root: %v", err)
		}
	})

	for _, name := range []string{"../escaped.json", "/absolute.json"} {
		if f, err := root.Create(name); err == nil {
			if err := f.Close(); err != nil {
				t.Errorf("closing %s: %v", name, err)
			}
			t.Errorf("Create(%q) was allowed, want it refused", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.json")); err == nil {
		t.Error("a file escaped the root")
	}
}

// TestUnpackReplacesPartialCopy checks that a copy left behind by an
// interrupted run is cleared, so its files cannot be mistaken for current ones.
func TestUnpackReplacesPartialCopy(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("closing the root: %v", err)
		}
	})

	stale := filepath.Join(dir, "etag1", "ID")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatalf("seeding a partial copy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stale, "GO-0000-0001.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("seeding a partial copy: %v", err)
	}

	if err := unpack(root, "etag1", zipWith(t, map[string]string{"index/db.json": `{}`})); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stale, "GO-0000-0001.json")); err == nil {
		t.Error("a file from the previous copy survived")
	}
}

func TestReadEtag(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("closing the root: %v", err)
		}
	})

	// Nothing recorded yet.
	if _, err := readEtag(root); err == nil {
		t.Error("expected an error when no version is recorded")
	}

	// A version whose directory is absent is meaningless, since the files it
	// names are what would be read.
	if err := os.WriteFile(filepath.Join(dir, etagFile), []byte("etag1\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", etagFile, err)
	}
	if _, err := readEtag(root); err == nil {
		t.Error("expected an error when the recorded directory is missing")
	}

	// With the directory present it is usable, and surrounding space is ignored.
	if err := os.MkdirAll(filepath.Join(dir, "etag1", "index"), 0o755); err != nil {
		t.Fatalf("creating the database directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etag1", "index", "db.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("writing db.json: %v", err)
	}
	got, err := readEtag(root)
	if err != nil {
		t.Fatalf("readEtag: %v", err)
	}
	if got != "etag1" {
		t.Errorf("got %q, want %q", got, "etag1")
	}
}

func TestCacheDirHonoursEnvironment(t *testing.T) {
	t.Setenv("GO_MOD_UPGRADE_CACHE", filepath.Join("custom", "cache"))
	got, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	if want := filepath.Join("custom", "cache"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
