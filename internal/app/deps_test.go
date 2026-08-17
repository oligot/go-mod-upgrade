package app

import (
	"path/filepath"
	"slices"
	"testing"
)

const listOutput = `
{
	"ImportPath": "example.com/main/cmd",
	"Module": {"Path": "example.com/main", "Main": true},
	"Imports": ["example.com/lib", "example.com/low", "fmt"]
}
{
	"ImportPath": "example.com/lib",
	"Module": {"Path": "example.com/lib"},
	"Imports": ["example.com/low", "example.com/lib/internal"]
}
{
	"ImportPath": "example.com/lib/internal",
	"Module": {"Path": "example.com/lib"},
	"Imports": ["example.com/low"]
}
{
	"ImportPath": "example.com/other",
	"Module": {"Path": "example.com/other"},
	"Imports": ["example.com/low"]
}
{
	"ImportPath": "example.com/low",
	"Module": {"Path": "example.com/low"},
	"Imports": ["fmt"]
}
{
	"ImportPath": "fmt"
}
`

func TestParseReverseDeps(t *testing.T) {
	deps, err := parseReverseDeps([]byte(listOutput))
	if err != nil {
		t.Fatalf("parseReverseDeps: %v", err)
	}

	// Three modules import example.com/low, and each is counted once even
	// though example.com/lib imports it from two packages.
	want := []string{"example.com/main", "example.com/lib", "example.com/other"}
	got := deps["example.com/low"]
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d entries", got, len(want))
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("dependents of example.com/low %v missing %s", got, w)
		}
	}

	// The module being worked on comes first, so that it survives truncation.
	if got[0] != "example.com/main" {
		t.Errorf("got %s first, want the main module", got[0])
	}

	// A package importing another in its own module says nothing about reach.
	if slices.Contains(deps["example.com/lib"], "example.com/lib") {
		t.Error("a module must not be listed as its own dependent")
	}
	// The standard library belongs to no module and cannot be upgraded.
	if _, ok := deps["fmt"]; ok {
		t.Error("standard library packages must not appear")
	}
	// Nothing imports the main module.
	if got := deps["example.com/main"]; len(got) != 0 {
		t.Errorf("got %v as dependents of the main module, want none", got)
	}
}

func TestParseReverseDepsInvalid(t *testing.T) {
	if _, err := parseReverseDeps([]byte("{oops")); err == nil {
		t.Error("expected an error for malformed input")
	}
}

func TestParseGraph(t *testing.T) {
	out := `
{"Path": "example.com/main", "Main": true}
{"Path": "example.com/direct", "Version": "v1.0.0"}
{"Path": "example.com/deep", "Version": "v0.3.0", "Indirect": true}
{"Path": "example.com/unknown"}
`
	reqs, err := parseGraph([]byte(out))
	if err != nil {
		t.Fatalf("parseGraph: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %v, want the two versioned dependencies", reqs)
	}

	byPath := map[string]requirement{}
	for _, r := range reqs {
		byPath[r.Path] = r
	}
	// The module being worked on has no version and cannot be upgraded.
	if _, ok := byPath["example.com/main"]; ok {
		t.Error("the main module must not be offered")
	}
	// Neither can one whose version could not be determined.
	if _, ok := byPath["example.com/unknown"]; ok {
		t.Error("a module with no version must not be offered")
	}
	if !byPath["example.com/deep"].Indirect {
		t.Error("example.com/deep is indirect, want Indirect true")
	}
	if byPath["example.com/direct"].Indirect {
		t.Error("example.com/direct is direct, want Indirect false")
	}
}

// TestRelativeToKeepsOrder guards the mapping the member prompt depends on:
// the name at each position has to describe the directory at that position,
// or a choice would be applied to the wrong module.
func TestRelativeToKeepsOrder(t *testing.T) {
	root := filepath.FromSlash("/w")
	all := []string{
		root,
		filepath.Join(root, "cmd", "osgen"),
		filepath.Join(root, "osotel"),
	}
	dirs := []string{
		filepath.Join(root, "osotel"),
		root,
		filepath.Join(root, "cmd", "osgen"),
	}

	names := relativeTo(dirs, all)
	// The root is named for its own directory rather than as ".", which would
	// name nothing a reader recognises among the members.
	want := []string{"osotel", "w", filepath.Join("cmd", "osgen")}
	if !slices.Equal(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}
}

func TestRelativeToSingleModule(t *testing.T) {
	dir := filepath.FromSlash("/w/only")
	// With one directory it is its own base, so there is nothing to trim and it
	// is named for itself.
	if got := relativeTo([]string{dir}, []string{dir}); !slices.Equal(got, []string{"only"}) {
		t.Errorf("got %v, want [only]", got)
	}
}

func TestCommonDir(t *testing.T) {
	root := filepath.FromSlash("/w")
	cases := []struct {
		name string
		dirs []string
		want string
	}{
		{
			name: "shared parent",
			dirs: []string{filepath.Join(root, "a"), filepath.Join(root, "b", "c")},
			want: root,
		},
		{
			name: "one contains the others",
			dirs: []string{root, filepath.Join(root, "a")},
			want: root,
		},
		{
			name: "single directory",
			dirs: []string{filepath.Join(root, "a")},
			want: filepath.Join(root, "a"),
		},
		{
			name: "none",
			dirs: nil,
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := commonDir(c.dirs); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}
