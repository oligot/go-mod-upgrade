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

	found := map[string]state{}
	if err := parseUpdates(out, found); err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}

	// A pseudo-version is reported like any other version.
	if got := found["github.com/mgutz/ansi"].Update; got == "" {
		t.Error("expected an update for github.com/mgutz/ansi")
	}
	if got := found["golang.org/x/text"].Update; got == "" {
		t.Error("expected an update for golang.org/x/text")
	}
	// go list -e reports an unresolvable module in the object rather than
	// failing, and it must not be offered as an update.
	if _, ok := found["github.com/definitely/not/a/module"]; ok {
		t.Error("a module that could not be resolved must not be reported")
	}
}

func TestParseUpdatesSkipsUnchanged(t *testing.T) {
	// A module already at the newest version has no Update field. It is still
	// recorded, since a policy has to see it, but with no version to move to.
	found := map[string]state{}
	err := parseUpdates([]byte(`{"Path":"example.com/m","Version":"v1.0.0"}`), found)
	if err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}
	if got := found["example.com/m"].Update; got != "" {
		t.Errorf("Update = %q, want empty for a current module", got)
	}
}

// TestParseUpdatesReadsDeprecationAndRetraction pins that the author's own
// signals are carried through rather than discarded.
//
// Both come from go list, so missing them is a matter of not asking: Deprecated
// needs -u and Retracted needs -retracted.
func TestParseUpdatesReadsDeprecationAndRetraction(t *testing.T) {
	const out = `{
	  "Path": "example.com/gone",
	  "Version": "v1.0.0",
	  "Deprecated": "Use example.com/successor instead.",
	  "Retracted": ["Published prematurely"]
	}`

	found := map[string]state{}
	if err := parseUpdates([]byte(out), found); err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}

	got := found["example.com/gone"]
	if got.Deprecated != "Use example.com/successor instead." {
		t.Errorf("Deprecated = %q, want the author's message", got.Deprecated)
	}
	if len(got.Retracted) != 1 || got.Retracted[0] != "Published prematurely" {
		t.Errorf("Retracted = %v, want the author's reason", got.Retracted)
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

// TestAssembleKeepsModulesWithNoUpdate pins that discovery reports every
// requirement, not only the upgradable ones.
//
// A module absent from the updates map is already at its newest version. It used
// to be dropped here, which removed it from the policy check as well as the
// listing, so an allow-list quietly permitted whatever happened to be current.
func TestAssembleKeepsModulesWithNoUpdate(t *testing.T) {
	wanted := []requirement{
		{Path: "example.com/current", Version: "v1.0.0"},
		{Path: "example.com/stale", Version: "v1.0.0"},
	}
	found := map[string]state{"example.com/stale": {Update: "v1.1.0"}}

	modules, err := assemble(wanted, found, nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(modules) != 2 {
		t.Fatalf("got %d modules, want both reported", len(modules))
	}

	byName := map[string]int{}
	for i, m := range modules {
		byName[m.Name] = i
	}

	// The current module stands where it is, which is how a caller tells it
	// apart from one with an upgrade available.
	current := modules[byName["example.com/current"]]
	if !current.From.Equal(current.To) {
		t.Errorf("current module: From %s, To %s, want them equal",
			current.From, current.To)
	}

	stale := modules[byName["example.com/stale"]]
	if stale.To.String() != "1.1.0" {
		t.Errorf("stale module: To = %s, want 1.1.0", stale.To)
	}
}

// TestAssembleMarksIgnoredWithoutDropping pins that --ignore marks a module
// rather than removing it, since a policy still has to see it.
func TestAssembleMarksIgnoredWithoutDropping(t *testing.T) {
	wanted := []requirement{{Path: "example.com/skipped", Version: "v1.0.0"}}
	found := map[string]state{"example.com/skipped": {Update: "v1.1.0"}}

	modules, err := assemble(wanted, found, []string{"skipped"})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(modules) != 1 {
		t.Fatalf("got %d modules, want the ignored module kept", len(modules))
	}
	if !modules[0].Ignored {
		t.Error("want the module marked as ignored")
	}
}

// TestAssembleCarriesDeprecationAndRetraction pins that the author's signals
// reach the module, since a policy is to be able to act on them.
func TestAssembleCarriesDeprecationAndRetraction(t *testing.T) {
	wanted := []requirement{{Path: "example.com/gone", Version: "v1.0.0"}}
	found := map[string]state{"example.com/gone": {
		Deprecated: "Use example.com/successor instead.",
		Retracted:  []string{"Published prematurely"},
	}}

	modules, err := assemble(wanted, found, nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(modules) != 1 {
		t.Fatalf("got %d modules, want one", len(modules))
	}
	mod := modules[0]
	if !mod.IsDeprecated() {
		t.Error("want the module reported as deprecated")
	}
	if !mod.IsRetracted() {
		t.Error("want the version reported as retracted")
	}
	// A deprecated module with nothing to upgrade to still stands where it is,
	// which is the case no upgrade resolves.
	if !mod.From.Equal(mod.To) {
		t.Errorf("From %s, To %s, want them equal", mod.From, mod.To)
	}
}
