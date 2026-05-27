package module

import (
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
