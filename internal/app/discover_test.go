package app

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/briandowns/spinner"
	"github.com/rs/zerolog/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// TestLogClearsTheSpinnerLine checks that a log entry written while a spinner is
// drawing starts at the beginning of the line.
//
// A spinner leaves the cursor part-way along a line, meaning to overwrite it by
// returning to column zero on its next tick. An entry written there joins it on
// that row, which is what a run reporting the vulnerability database mid-sweep
// produced: "Scanning for vulnerabilities (0/1)   • Vulnerability database ..." on
// one line. Clearing first is what keeps them apart.
func TestLogClearsTheSpinnerLine(t *testing.T) {
	var buf bytes.Buffer
	defer setProgressOutput(&buf)()
	// Stands in for a spinner that started drawing, which needs a terminal the
	// tests do not have.
	defer holdForTest(spinner.New(spinner.CharSets[14], time.Hour))()

	log.Debug().Str("dir", "/path/member0").Msg("Scanning")

	if got := buf.String(); !strings.HasPrefix(got, "\r\033[K") {
		t.Errorf("entry %q does not begin by clearing the line", got)
	}
}

// TestLogWritesPlainlyWithNothingDrawing checks that an entry carries no escape
// sequence when no spinner is drawing, which covers both a run with none and one
// whose output is not a terminal: a spinner declines to draw without one, and
// clearing a line that was never drawn would corrupt a captured log.
func TestLogWritesPlainlyWithNothingDrawing(t *testing.T) {
	var buf bytes.Buffer
	defer setProgressOutput(&buf)()

	// track starts a spinner, which does not draw because a buffer is not a
	// terminal, so nothing registers and nothing is cleared.
	c, err := track("testing", 1)
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	defer c.Stop()

	log.Debug().Str("dir", "/path/member0").Msg("Scanning")

	if got := buf.String(); strings.Contains(got, "\033[K") {
		t.Errorf("output %q clears a line that was never drawn", got)
	}
}

func TestParseRequirements(t *testing.T) {
	out, err := os.ReadFile("testdata/gomod_replace.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	mod, err := parseRequirements(out)
	if err != nil {
		t.Fatalf("parseRequirements: %v", err)
	}

	byPath := map[string]requirement{}
	for _, r := range mod.Reqs {
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
	if _, ok := mod.Skip["github.com/pkg/errors"]; !ok {
		t.Error("locally replaced github.com/pkg/errors must be skipped")
	}
	// A replacement naming a version can still be queried.
	if _, ok := mod.Skip["github.com/mgutz/ansi"]; ok {
		t.Error("github.com/mgutz/ansi is replaced with a version, want it queried")
	}
}

// TestParseRequirementsReadsToolchain checks that the directives deciding which
// standard library is in use are read, since a stdlib advisory is reported
// against them rather than against a module.
func TestParseRequirementsReadsToolchain(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "the go directive alone",
			body: `{"Module":{"Path":"example.com/m"},"Go":"1.25.9"}`,
			want: "1.25.9",
		},
		{
			// A toolchain directive names what will actually build the module,
			// so it decides rather than the language version.
			name: "a toolchain overrides it",
			body: `{"Module":{"Path":"example.com/m"},"Go":"1.24","Toolchain":"go1.25.9"}`,
			want: "1.25.9",
		},
		{
			name: "neither",
			body: `{"Module":{"Path":"example.com/m"}}`,
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mod, err := parseRequirements([]byte(c.body))
			if err != nil {
				t.Fatalf("parseRequirements: %v", err)
			}
			if got := mod.stdlibVersion(); got != c.want {
				t.Errorf("stdlibVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseRequirementsEmpty(t *testing.T) {
	mod, err := parseRequirements([]byte(`{"Module":{"Path":"example.com/m"},"Go":"1.24"}`))
	if err != nil {
		t.Fatalf("parseRequirements: %v", err)
	}
	if len(mod.Reqs) != 0 {
		t.Errorf("got %d requirements for a go.mod with no require block, want 0", len(mod.Reqs))
	}
	if len(mod.Skip) != 0 {
		t.Errorf("got %d skipped modules, want 0", len(mod.Skip))
	}
}

func TestParseRequirementsInvalid(t *testing.T) {
	if _, err := parseRequirements([]byte("not json")); err == nil {
		t.Error("expected an error for malformed input")
	}
}

// TestParseUpdatesReadsReleaseTime checks that when a version was published is
// carried through, since how fresh a release is decides whether to recommend it.
//
// go list reports it alongside the version, so it costs nothing to ask for. The date
// is taken whether or not an upgrade is available: a module already at its newest
// still has a release date, and a listing shows it.
func TestParseUpdatesReadsReleaseTime(t *testing.T) {
	out, err := os.ReadFile("testdata/golist_updates.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	found := map[string]state{}
	if err := parseUpdates(out, found); err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}

	// The fixture's x/text upgrade was published on a date go list reports.
	got := found["golang.org/x/text"]
	if got.Released.IsZero() {
		t.Fatal("golang.org/x/text carries no release date")
	}
	if want := "2026-07-08"; got.Released.Format("2006-01-02") != want {
		t.Errorf("released %s, want %s", got.Released.Format("2006-01-02"), want)
	}
}

// TestParseUpdatesReadsReleaseTimeWithoutUpgrade checks that a module already at its
// newest version still carries a date, which is what lets a listing say how old the
// version in use is.
func TestParseUpdatesReadsReleaseTimeWithoutUpgrade(t *testing.T) {
	const body = `{
	  "Path": "example.com/current",
	  "Version": "v1.0.0",
	  "Time": "2026-01-02T03:04:05Z"
	}`

	found := map[string]state{}
	if err := parseUpdates([]byte(body), found); err != nil {
		t.Fatalf("parseUpdates: %v", err)
	}

	got := found["example.com/current"]
	if got.Update != "" {
		t.Errorf("Update = %q, want empty for a current module", got.Update)
	}
	if want := "2026-01-02"; got.Released.Format("2006-01-02") != want {
		t.Errorf("released %s, want %s", got.Released.Format("2006-01-02"), want)
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
	// go list -e reports a failed lookup in the object rather than failing, and the
	// fixture's is an authentication rejection: git could not read a username, so
	// nothing was learned about what the module has published. It is recorded as
	// unknown rather than dropped, since a dropped module reads as standing at the
	// version in use -- indistinguishable from one with nothing newer.
	failed, ok := found["github.com/definitely/not/a/module"]
	if !ok {
		t.Fatal("a module whose lookup failed must still be reported")
	}
	if !failed.Unknown {
		t.Error("a module whose lookup failed must be marked unknown, not current")
	}
	if failed.Update != "" {
		t.Errorf("Update = %q, want nothing offered for an unchecked module", failed.Update)
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
	}, true)

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

// TestQueryArgsDropsUpgradeCheck checks that -u is the only part that comes and goes.
//
// -u is what asks the proxy what has been published, and the only part of this that touches the
// network -- a second against a fiftieth of one. The rest describes what is installed and is
// read from the module cache, so it is asked for either way: a go.mod edited since a remembered
// answer would otherwise be reported against the wrong requirements.
func TestQueryArgsDropsUpgradeCheck(t *testing.T) {
	reqs := []requirement{{Path: "golang.org/x/text", Version: "v0.4.0"}}

	with := queryArgs(reqs, true)
	if !slices.Contains(with, "-u") {
		t.Errorf("args %v lack -u, want the upgrade check", with)
	}
	without := queryArgs(reqs, false)
	if slices.Contains(without, "-u") {
		t.Errorf("args %v carry -u, want it dropped", without)
	}
	// Everything else is unchanged, since it describes the tree rather than the proxy.
	for _, want := range []string{"-retracted", "-e", "-json", "golang.org/x/text@v0.4.0"} {
		if !slices.Contains(without, want) {
			t.Errorf("args %v missing %q", without, want)
		}
	}
}

// TestDiscoverAcrossReportsEveryDirectory checks that discovering several modules at once returns
// one result per directory, in the order they were given.
//
// A workspace member's build list resolves independently of the others, and Go redoes that work
// per invocation -- 0.06s from the workspace root against 0.70s from a member, for the same
// modules. Five members read one after another is the whole cost of the phase, and they are
// independent, so they are read at once.
//
// In order because everything downstream merges them into shared maps, and a run must report the
// same thing however the reads happened to finish.
func TestDiscoverAcrossReportsEveryDirectory(t *testing.T) {
	dirs := []string{"a", "b", "c", "d", "e"}
	var mu sync.Mutex
	seen := map[string]int{}

	got := discoverAcross(dirs, func(dir string) (string, error) {
		mu.Lock()
		seen[dir]++
		mu.Unlock()
		if dir == "c" {
			return "", errUnreachable
		}
		return "found:" + dir, nil
	})

	if len(got) != len(dirs) {
		t.Fatalf("got %d results, want one per directory", len(got))
	}
	for i, dir := range dirs {
		if got[i].dir != dir {
			t.Errorf("[%d] is %q, want %q: the order must not depend on which finished first",
				i, got[i].dir, dir)
		}
		if seen[dir] != 1 {
			t.Errorf("%q was read %d times, want once", dir, seen[dir])
		}
	}
	// A failure is held by position rather than ending the others: one unreadable member
	// should not hide the upgrades available in the rest of the workspace.
	if got[2].err == nil {
		t.Error("the failing directory reports no error, want it held")
	}
	for _, at := range []int{0, 1, 3, 4} {
		if got[at].err != nil || got[at].value == "" {
			t.Errorf("[%d] = %+v, want a result despite the failure elsewhere", at, got[at])
		}
	}
}

// TestAssembleReportsAnUncheckedModuleAsUnchecked pins the consequence at the far end.
//
// The state parseUpdates records is only worth recording if it survives to the row, and Unchecked
// is what a listing renders as unchecked rather than as a version. A module marked unknown and one
// with nothing newer both carry to == from, so the flag is the only thing separating "nothing
// newer exists" from "nobody asked".
func TestAssembleReportsAnUncheckedModuleAsUnchecked(t *testing.T) {
	wanted := []requirement{
		{Path: "example.com/checked", Version: "v1.0.0"},
		{Path: "example.com/unchecked", Version: "v1.0.0"},
	}
	found := map[string]state{
		"example.com/checked":   {},
		"example.com/unchecked": {Unknown: true},
	}

	modules, err := assemble(wanted, found, nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(modules) != 2 {
		t.Fatalf("got %d modules, want 2", len(modules))
	}

	by := map[string]module.Module{}
	for _, m := range modules {
		by[m.Name] = m
	}
	if by["example.com/checked"].Unchecked {
		t.Error("a module the proxy answered about must be reported as checked")
	}
	if !by["example.com/unchecked"].Unchecked {
		t.Error("a module nothing was learned about must be reported as unchecked")
	}
	// Both stand at the version they hold, which is why the flag has to carry the difference.
	for _, name := range []string{"example.com/checked", "example.com/unchecked"} {
		if got := by[name]; !got.From.Equal(got.To) {
			t.Errorf("%s moves from %s to %s, want it standing still", name, got.From, got.To)
		}
	}
}
