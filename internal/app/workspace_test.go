package app

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeModule creates a directory holding a minimal go.mod.
func writeModule(t *testing.T, dir, path string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", dir, err)
	}
	content := "module " + path + "\n\ngo 1.24\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing go.mod in %s: %v", dir, err)
	}
}

// writeWork creates a go.work file holding the given use directives and
// returns its path.
func writeWork(t *testing.T, dir string, uses ...string) string {
	t.Helper()
	content := "go 1.24\n\nuse (\n"
	for _, u := range uses {
		content += "\t" + u + "\n"
	}
	content += ")\n"
	gowork := filepath.Join(dir, "go.work")
	if err := os.WriteFile(gowork, []byte(content), 0o644); err != nil {
		t.Fatalf("writing go.work: %v", err)
	}
	return gowork
}

// TestWorkspaceDirsResolvesPaths checks that use directives are resolved
// against the directory holding the work file, whatever form they take.
func TestWorkspaceDirsResolvesPaths(t *testing.T) {
	// The work file sits in a subdirectory so that a parent-relative use
	// directive has somewhere to point.
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	writeModule(t, root, "example.com/root")
	writeModule(t, filepath.Join(root, "a"), "example.com/a")
	writeModule(t, filepath.Join(base, "sibling"), "example.com/sibling")
	absolute := filepath.Join(base, "absolute")
	writeModule(t, absolute, "example.com/absolute")

	gowork := writeWork(t, root, ".", "./a", "../sibling", absolute)

	dirs, err := workspaceDirs(gowork)
	if err != nil {
		t.Fatalf("workspaceDirs: %v", err)
	}

	want := []string{
		root,
		filepath.Join(root, "a"),
		filepath.Join(base, "sibling"),
		absolute,
	}
	if len(dirs) != len(want) {
		t.Fatalf("got %d directories (%v), want %d", len(dirs), dirs, len(want))
	}
	for _, w := range want {
		if !slices.Contains(dirs, w) {
			t.Errorf("directories %v missing %s", dirs, w)
		}
	}
}

// TestWorkspaceDirsDeduplicates checks that a directory named twice is only
// offered once, so its updates are not listed twice.
func TestWorkspaceDirsDeduplicates(t *testing.T) {
	root := t.TempDir()
	writeModule(t, filepath.Join(root, "a"), "example.com/a")

	gowork := writeWork(t, root, "./a", "./a", "./a/../a")

	dirs, err := workspaceDirs(gowork)
	if err != nil {
		t.Fatalf("workspaceDirs: %v", err)
	}
	if len(dirs) != 1 {
		t.Errorf("got %v, want the directory once", dirs)
	}
}

// TestWorkspaceDirsSkipsMissingModule checks that a use directive naming a
// directory without a go.mod does not stop the remaining modules from being
// processed.
func TestWorkspaceDirsSkipsMissingModule(t *testing.T) {
	root := t.TempDir()
	writeModule(t, filepath.Join(root, "present"), "example.com/present")
	// A directory that exists but holds no go.mod.
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o755); err != nil {
		t.Fatalf("creating empty: %v", err)
	}

	gowork := writeWork(t, root, "./empty", "./present", "./absent")

	dirs, err := workspaceDirs(gowork)
	if err != nil {
		t.Fatalf("workspaceDirs: %v", err)
	}
	want := []string{filepath.Join(root, "present")}
	if !slices.Equal(dirs, want) {
		t.Errorf("got %v, want %v", dirs, want)
	}
}

func TestWorkspaceDirsMalformed(t *testing.T) {
	root := t.TempDir()
	gowork := filepath.Join(root, "go.work")
	if err := os.WriteFile(gowork, []byte("this is not a work file\n"), 0o644); err != nil {
		t.Fatalf("writing go.work: %v", err)
	}
	if _, err := workspaceDirs(gowork); err == nil {
		t.Error("expected an error for a malformed work file")
	}
}

func TestWorkspaceDirsMissingFile(t *testing.T) {
	if _, err := workspaceDirs(filepath.Join(t.TempDir(), "go.work")); err == nil {
		t.Error("expected an error when the work file does not exist")
	}
}
