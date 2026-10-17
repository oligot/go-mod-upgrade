package module

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteImportsInProject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "go-rewrite-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	goCode := `package main

import (
	"fmt"
	"github.com/foo/bar"
	"github.com/foo/bar/subpkg"
	"github.com/foo/bar-other"
)

func main() {
	fmt.Println("test")
}`

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(goCode), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	if err := RewriteImportsInProject(tmpDir, "github.com/foo/bar", "github.com/foo/bar/v2"); err != nil {
		t.Fatalf("unexpected error rewriting imports: %v", err)
	}

	updated, err := os.ReadFile(filepath.Join(tmpDir, "main.go"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	sUpdated := string(updated)
	if !strings.Contains(sUpdated, `"github.com/foo/bar/v2"`) {
		t.Error("expected github.com/foo/bar to be rewritten to v2")
	}
	if !strings.Contains(sUpdated, `"github.com/foo/bar/v2/subpkg"`) {
		t.Error("expected subpackage to be rewritten to v2")
	}
	if !strings.Contains(sUpdated, `"github.com/foo/bar-other"`) {
		t.Error("expected similar package name to remain untouched")
	}
}

const rewriteSrc = "package x\n\nimport \"github.com/foo/bar\"\n"

func writeGoFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(rewriteSrc), 0644); err != nil {
		t.Fatal(err)
	}
}

func readGoFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestRewriteImportsInProject_SkipsTestdata(t *testing.T) {
	root := t.TempDir()
	rewritten := []string{"main.go", "testdata_helper.go", "mytestdata/x.go"}
	untouched := []string{"testdata/golden.go", "sub/testdata/golden.go"}
	for _, name := range append(rewritten, untouched...) {
		writeGoFile(t, filepath.Join(root, name))
	}

	if err := RewriteImportsInProject(root, "github.com/foo/bar", "github.com/foo/bar/v2"); err != nil {
		t.Fatalf("unexpected error rewriting imports: %v", err)
	}

	for _, name := range rewritten {
		if !bytes.Contains(readGoFile(t, filepath.Join(root, name)), []byte(`"github.com/foo/bar/v2"`)) {
			t.Errorf("expected %s to be rewritten", name)
		}
	}
	for _, name := range untouched {
		if !bytes.Equal(readGoFile(t, filepath.Join(root, name)), []byte(rewriteSrc)) {
			t.Errorf("expected %s to be byte-identical", name)
		}
	}
}

func TestRewriteImportsInProject_RootNamedTestdata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "testdata")
	writeGoFile(t, filepath.Join(root, "main.go"))

	if err := RewriteImportsInProject(root, "github.com/foo/bar", "github.com/foo/bar/v2"); err != nil {
		t.Fatalf("unexpected error rewriting imports: %v", err)
	}

	if !bytes.Contains(readGoFile(t, filepath.Join(root, "main.go")), []byte(`"github.com/foo/bar/v2"`)) {
		t.Error("expected main.go under a root named testdata to be rewritten")
	}
}
