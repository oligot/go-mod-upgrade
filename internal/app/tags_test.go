package app

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// write puts a Go file in a directory, creating parents as needed.
func write(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

// TestSolveMinimalTags checks that an expression yields the least a caller would
// have to pass, since the tags are reported as the configuration to reproduce.
func TestSolveMinimalTags(t *testing.T) {
	cases := []struct {
		expr string
		want []string
		ok   bool
	}{
		// An or-group needs only one of its arms.
		{"integration && (core || opensearchapi)", []string{"core", "integration"}, true},
		{"integration", []string{"integration"}, true},
		// A negated tag is satisfied by leaving it unset, so it adds nothing.
		{"integration && core && !multinode", []string{"core", "integration"}, true},
		{"integration && (core || opensearchtransport) && multinode",
			[]string{"core", "integration", "multinode"}, true},
		// Satisfied by setting nothing at all, which is the default
		// configuration and needs no set of its own.
		{"!integration", nil, false},
		// A file no build includes is not a configuration to analyse.
		{"ignore", nil, false},
		// Unsatisfiable however the tags are set.
		{"integration && !integration", nil, false},
		{"not a constraint at all", nil, false},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			got, ok := solve(c.expr)
			if ok != c.ok {
				t.Fatalf("satisfiable = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if !slices.Equal(got.Tags, c.want) {
				t.Errorf("tags = %v, want %v", got.Tags, c.want)
			}
		})
	}
}

// TestSolveIgnoresToolchainTags checks that a constraint the toolchain decides is
// not offered as a configuration to choose.
//
// A release or GOEXPERIMENT cannot be satisfied by passing -tags, so sweeping for
// one would be a wasted pass reporting the same thing as the default.
func TestSolveIgnoresToolchainTags(t *testing.T) {
	for _, expr := range []string{"go1.24", "goexperiment.jsonv2", "go1.99"} {
		if _, ok := solve(expr); ok {
			t.Errorf("%q was offered as a tag set, want it left to the toolchain", expr)
		}
	}
}

// TestTagSetsDefaultFirst checks that a project with no constraints yields the one
// configuration a plain build sees.
func TestTagSetsDefaultFirst(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	sets, err := tagSets(dir)
	if err != nil {
		t.Fatalf("tagSets: %v", err)
	}
	if len(sets) != 1 {
		t.Fatalf("got %d sets, want just the default: %v", len(sets), sets)
	}
	if got := sets[0].Name(); got != defaultTagSet {
		t.Errorf("first set = %q, want %q", got, defaultTagSet)
	}
	if len(sets[0].Tags) != 0 {
		t.Errorf("default set carries tags %v, want none", sets[0].Tags)
	}
}

// TestTagSetsFromConstraints checks that each distinct constraint contributes a
// configuration, and that two solving to the same tags contribute one.
func TestTagSetsFromConstraints(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "package main\n\nfunc main() {}\n")
	write(t, dir, "unit_test.go", "//go:build !integration\n\npackage main\n")
	write(t, dir, "it_test.go", "//go:build integration\n\npackage main\n")
	// These two solve to the same tags, so they collapse into one set.
	write(t, dir, "core_test.go", "//go:build integration && core\n\npackage main\n")
	write(t, dir, "core2_test.go", "//go:build integration && core && !multinode\n\npackage main\n")

	sets, err := tagSets(dir)
	if err != nil {
		t.Fatalf("tagSets: %v", err)
	}

	var names []string
	for _, s := range sets {
		names = append(names, s.Name())
	}
	// The default leads; the rest follow in the order of the constraint text they
	// came from, so a listing does not shuffle between runs.
	want := []string{defaultTagSet, "integration", "core,integration"}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}

	// The set names the expression it came from, which says more than the tags
	// solving it.
	for _, s := range sets {
		if s.Name() == defaultTagSet {
			continue
		}
		if s.From == "" {
			t.Errorf("set %q does not name the constraint it satisfies", s.Name())
		}
	}
}

// TestConstraintsSkipsNonSource checks that only the project's own Go files are
// read: a vendored dependency's constraints are its business, and a testdata
// fixture is not built at all.
func TestConstraintsSkipsNonSource(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "//go:build mine\n\npackage main\n")
	write(t, dir, "vendor/example.com/dep/dep.go", "//go:build theirs\n\npackage dep\n")
	write(t, dir, "testdata/fixture.go", "//go:build fixture\n\npackage fixture\n")
	write(t, dir, ".git/hooks/hook.go", "//go:build hook\n\npackage hook\n")
	write(t, dir, "_ignored/old.go", "//go:build old\n\npackage old\n")
	write(t, dir, "notes.txt", "//go:build text\n")

	found, err := constraints(dir)
	if err != nil {
		t.Fatalf("constraints: %v", err)
	}
	if _, ok := found["mine"]; !ok {
		t.Error("the project's own constraint was not found")
	}
	for _, absent := range []string{"theirs", "fixture", "hook", "old", "text"} {
		if _, ok := found[absent]; ok {
			t.Errorf("constraint %q was read, want it skipped", absent)
		}
	}
}

// TestBuildLineStopsAtPackage checks that only the header is read. A constraint
// has to precede the package clause, so a "//go:build" comment further down is
// not one.
func TestBuildLineStopsAtPackage(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.go", "//go:build real\n\npackage main\n\n//go:build notaconstraint\n")

	got, err := buildLine(filepath.Join(dir, "a.go"))
	if err != nil {
		t.Fatalf("buildLine: %v", err)
	}
	if got != "real" {
		t.Errorf("got %q, want %q", got, "real")
	}

	write(t, dir, "b.go", "package main\n\n//go:build toolate\n")
	got, err = buildLine(filepath.Join(dir, "b.go"))
	if err != nil {
		t.Fatalf("buildLine: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want nothing after the package clause", got)
	}
}
