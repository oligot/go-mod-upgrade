package module

import (
	"os"
	"strings"
	"testing"
)

func TestRewriteImportsInProject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "go-rewrite-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}
	defer os.Chdir(cwd)

	// Write mock .go file
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

	if err := os.WriteFile("main.go", []byte(goCode), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	err = RewriteImportsInProject("github.com/foo/bar", "github.com/foo/bar/v2")
	if err != nil {
		t.Fatalf("unexpected error rewriting imports: %v", err)
	}

	updated, err := os.ReadFile("main.go")
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
