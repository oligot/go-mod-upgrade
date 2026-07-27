package app

import (
	"os"
	"slices"
	"testing"
)

func TestParseRequirements(t *testing.T) {
	out, err := os.ReadFile("testdata/gomod_replace.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	reqs, skip, err := parseRequirements(out)
	if err != nil {
		t.Fatalf("parseRequirements: %v", err)
	}

	byPath := map[string]requirement{}
	for _, r := range reqs {
		byPath[r.Path] = r
	}

	// A module in the first require block is a direct dependency.
	if got, ok := byPath["github.com/urfave/cli/v3"]; !ok {
		t.Error("expected github.com/urfave/cli/v3 among the requirements")
	} else if got.Indirect {
		t.Error("github.com/urfave/cli/v3 is required directly, want Indirect false")
	}

	// A module carrying the "// indirect" comment is not a direct dependency.
	if got, ok := byPath["golang.org/x/sys"]; !ok {
		t.Error("expected golang.org/x/sys among the requirements")
	} else if !got.Indirect {
		t.Error("golang.org/x/sys is required indirectly, want Indirect true")
	}

	// A replacement pointing at a directory has no version to query.
	if !skip["github.com/pkg/errors"] {
		t.Error("locally replaced github.com/pkg/errors must be skipped")
	}
	// A replacement naming a version can still be queried.
	if skip["github.com/mgutz/ansi"] {
		t.Error("github.com/mgutz/ansi is replaced with a version, want it queried")
	}
}

func TestParseRequirementsEmpty(t *testing.T) {
	reqs, skip, err := parseRequirements([]byte(`{"Module":{"Path":"example.com/m"},"Go":"1.24"}`))
	if err != nil {
		t.Fatalf("parseRequirements: %v", err)
	}
	if len(reqs) != 0 {
		t.Errorf("got %d requirements for a go.mod with no require block, want 0", len(reqs))
	}
	if len(skip) != 0 {
		t.Errorf("got %d skipped modules, want 0", len(skip))
	}
}

func TestParseRequirementsInvalid(t *testing.T) {
	if _, _, err := parseRequirements([]byte("not json")); err == nil {
		t.Error("expected an error for malformed input")
	}
}

func TestParseUpdates(t *testing.T) {
	out, err := os.ReadFile("testdata/golist_updates.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	found := map[string]string{}
	if err := parseUpdates(out, found); err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}

	// A pseudo-version is reported like any other version.
	if got := found["github.com/mgutz/ansi"]; got == "" {
		t.Error("expected an update for github.com/mgutz/ansi")
	}
	if got := found["golang.org/x/text"]; got == "" {
		t.Error("expected an update for golang.org/x/text")
	}
	// go list -e reports an unresolvable module in the object rather than
	// failing, and it must not be offered as an update.
	if _, ok := found["github.com/definitely/not/a/module"]; ok {
		t.Error("a module that could not be resolved must not be reported")
	}
}

func TestParseUpdatesSkipsUnchanged(t *testing.T) {
	// A module already at the newest version has no Update field.
	found := map[string]string{}
	err := parseUpdates([]byte(`{"Path":"example.com/m","Version":"v1.0.0"}`), found)
	if err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("got %v, want no updates", found)
	}
}

func TestQueryArgs(t *testing.T) {
	args := queryArgs([]requirement{
		{Path: "golang.org/x/text", Version: "v0.4.0"},
		{Path: "github.com/mgutz/ansi", Version: "v0.0.0-20170206155736-9520e82c474b"},
	})

	// Querying path@version keeps the lookup independent of the main module's
	// build list, so an incomplete go.sum cannot fail the run.
	for _, want := range []string{
		"golang.org/x/text@v0.4.0",
		"github.com/mgutz/ansi@v0.0.0-20170206155736-9520e82c474b",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
	// -e keeps one unreachable module from failing the whole batch.
	if !slices.Contains(args, "-e") {
		t.Errorf("args %v missing -e", args)
	}
	// -mod=readonly rejects a workspace, see issue 25.
	if slices.Contains(args, "-mod=readonly") {
		t.Errorf("args %v must not set -mod=readonly", args)
	}
}
