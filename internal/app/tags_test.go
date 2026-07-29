package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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
			f, parsed := parseFilter(c.expr)
			if !parsed {
				if c.ok {
					t.Fatalf("parseFilter(%q) failed, want it usable", c.expr)
				}
				return
			}
			got, ok := f.satisfy()
			// A predicate satisfied by setting nothing describes the default
			// configuration, which the discovery step drops rather than scanning
			// twice.
			usable := ok && len(got) > 0
			if usable != c.ok {
				t.Fatalf("usable = %v, want %v (tags %v, satisfiable %v)", usable, c.ok, got, ok)
			}
			if !usable {
				return
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("tags = %v, want %v", got, c.want)
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
		f, ok := parseFilter(expr)
		if !ok {
			t.Fatalf("parseFilter(%q) failed", expr)
		}
		if tags, _ := f.satisfy(); len(tags) > 0 {
			t.Errorf("%q wants tags %v, want it left to the toolchain", expr, tags)
		}
	}
}

// TestTagSetsDefaultFirst checks that a project with no constraints yields the one
// configuration a plain build sees.
func TestTagSetsDefaultFirst(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "package main\n\nfunc main() {}\n")

	filters, err := discoverFilters(dir)
	if err != nil {
		t.Fatalf("discoverFilters: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("got %d filters, want just the default: %v", len(filters), filters)
	}
	if got := filters[0].String(); got != defaultTagSet {
		t.Errorf("first filter = %q, want %q", got, defaultTagSet)
	}
	if tags, _ := filters[0].satisfy(); len(tags) != 0 {
		t.Errorf("default filter wants tags %v, want none", tags)
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

	filters, err := discoverFilters(dir)
	if err != nil {
		t.Fatalf("discoverFilters: %v", err)
	}

	// The default leads; the rest follow in the order of the constraint text they
	// came from, so a listing does not shuffle between runs. A filter names the
	// expression it came from, which says more than the tags satisfying it.
	var names []string
	for _, f := range filters {
		names = append(names, f.String())
	}
	want := []string{defaultTagSet, "integration", "integration && core"}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
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

// found builds the configurations a discovery pass would have turned up, for
// testing how --tags adjusts them.
func found(t *testing.T, exprs ...string) []tagFilter {
	t.Helper()
	filters := []tagFilter{{}}
	for _, expr := range exprs {
		f, ok := parseFilter(expr)
		if !ok {
			t.Fatalf("parseFilter(%q) failed", expr)
		}
		filters = append(filters, f)
	}
	return filters
}

// names renders the configurations for comparison.
func names(filters []tagFilter) []string {
	var out []string
	for _, f := range filters {
		out = append(out, f.String())
	}
	return out
}

// TestParseTagsDefaults checks that saying nothing keeps what discovery found.
func TestParseTagsDefaults(t *testing.T) {
	have := found(t, "integration")
	got, err := ParseTags(nil, have)
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	if want := []string{defaultTagSet, "integration"}; !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

// TestParseTagsReplaces checks that an unsigned value overrides discovery, which
// is the escape hatch for a project with more configurations than anyone wants
// scanned.
func TestParseTagsReplaces(t *testing.T) {
	have := found(t, "integration", "integration && core")
	got, err := ParseTags([]string{"integration && core && !multinode"}, have)
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	want := []string{"integration && core && !multinode"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v: an unsigned value replaces the default", names(got), want)
	}
}

// TestParseTagsAdds checks that a "+" value adds a configuration to scan without
// naming the others.
func TestParseTagsAdds(t *testing.T) {
	have := found(t, "integration")
	got, err := ParseTags([]string{"+integration && core && !multinode"}, have)
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	want := []string{defaultTagSet, "integration", "integration && core && !multinode"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

// TestParseTagsRemoves checks that a "-" value drops the configurations its
// predicate describes.
//
// "-integration" means "not the integration configurations", so every discovered
// one whose tags satisfy it goes, leaving the default.
func TestParseTagsRemoves(t *testing.T) {
	have := found(t, "integration", "integration && core")
	got, err := ParseTags([]string{"-integration"}, have)
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	if want := []string{defaultTagSet}; !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

// TestParseTagsRemovesSelectively checks that subtracting a narrower predicate
// leaves the configurations it does not describe.
func TestParseTagsRemovesSelectively(t *testing.T) {
	have := found(t, "integration", "integration && core")
	// Only the configuration setting both goes; plain "integration" stays, since
	// its tags do not satisfy "integration && core".
	got, err := ParseTags([]string{"-integration && core"}, have)
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	want := []string{defaultTagSet, "integration"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

// TestParseTagsRejectsMixedForms checks that naming configurations and adjusting
// them in one invocation is refused, since it could mean either.
func TestParseTagsRejectsMixedForms(t *testing.T) {
	_, err := ParseTags([]string{"integration", "+integration && core"}, found(t))
	if err == nil {
		t.Fatal("expected an error for a value mixing naming with adjusting")
	}
	if !strings.Contains(err.Error(), "mixes") {
		t.Errorf("error %q does not explain the problem", err)
	}
}

func TestParseTagsUnparseable(t *testing.T) {
	if _, err := ParseTags([]string{"+not a constraint"}, found(t)); err == nil {
		t.Error("expected an error for an unparseable predicate")
	}
}

// TestParseTagsAddsOnce checks that naming the same configuration twice asks for
// it once, whether in one value or across several.
//
// Each configuration costs a full analysis pass, so a repeated one would spend
// that pass to report what the first already reported.
func TestParseTagsAddsOnce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		specs []string
	}{
		{"several values", []string{"+integration", "+integration"}},
		// Two expressions wanting the same tags describe one configuration, which
		// is the rule discovery already applies to the project's own constraints.
		{"same tags spelled differently", []string{"+integration", "+integration && integration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTags(tc.specs, found(t))
			if err != nil {
				t.Fatalf("ParseTags: %v", err)
			}
			want := []string{defaultTagSet, "integration"}
			if !slices.Equal(names(got), want) {
				t.Errorf("got %v, want %v", names(got), want)
			}
		})
	}
}

// TestParseTagsAddsOnceOverDiscovered checks that adding a configuration
// discovery already found leaves it named once.
func TestParseTagsAddsOnceOverDiscovered(t *testing.T) {
	got, err := ParseTags([]string{"+integration"}, found(t, "integration"))
	if err != nil {
		t.Fatalf("ParseTags: %v", err)
	}
	want := []string{defaultTagSet, "integration"}
	if !slices.Equal(names(got), want) {
		t.Errorf("got %v, want %v", names(got), want)
	}
}

// TestParseTagsRejectsBareSign checks that a sign with no predicate is refused.
//
// It is a typo rather than a request: stripping the sign leaves nothing, and
// nothing describes the default configuration, so accepting it would quietly ask
// for a second default pass instead of reporting the mistake.
func TestParseTagsRejectsBareSign(t *testing.T) {
	for _, spec := range []string{"+", "-", "+ ", "- "} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ParseTags([]string{spec}, found(t)); err == nil {
				t.Errorf("ParseTags(%q): expected an error for a sign with no predicate", spec)
			}
		})
	}
}
