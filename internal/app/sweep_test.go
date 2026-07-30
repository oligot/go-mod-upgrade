package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// filters builds a set of configurations for a test: the default, plus one per
// expression named.
func filters(t *testing.T, exprs ...string) []tagFilter {
	t.Helper()
	out := []tagFilter{{}}
	for _, expr := range exprs {
		f, ok := parseFilter(expr)
		if !ok {
			t.Fatalf("parseFilter(%q) failed", expr)
		}
		out = append(out, f)
	}
	return out
}

// TestTagArgs checks what each configuration passes to the toolchain. The default
// passes nothing: "-tags=" is not the same as omitting the flag.
func TestTagArgs(t *testing.T) {
	set := filters(t, "integration", "integration && core")
	cases := []struct {
		at   int
		want []string
	}{
		{0, nil},
		{1, []string{"-tags=integration"}},
		{2, []string{"-tags=core,integration"}},
	}
	for _, c := range cases {
		if got := set[c.at].tagArgs(); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", set[c.at], got, c.want)
		}
	}
}

// TestSweepRunsEveryConfiguration checks that each configuration gets a pass and
// that the results come back in the order the configurations were given, whatever
// order the passes finish in.
func TestSweepRunsEveryConfiguration(t *testing.T) {
	set := filters(t, "integration", "integration && core")

	got, err := sweep(context.Background(), "testing", set,
		func(_ context.Context, f tagFilter) (string, error) {
			return f.String(), nil
		})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	want := []string{defaultTagSet, "integration", "integration && core"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v: results must line up with the configurations", got, want)
	}
}

// TestSweepReportsEveryFailedPass checks that several failing configurations are
// all reported, in the order the configurations were given.
//
// Reporting only one would hide the rest, and since the passes are drained as they
// complete, which one survived would vary between runs on the same input.
func TestSweepReportsEveryFailedPass(t *testing.T) {
	set := filters(t, "integration", "integration && core")
	first := errors.New("could not load packages")
	second := errors.New("no such tool")

	got, err := sweep(context.Background(), "testing", set,
		func(_ context.Context, f tagFilter) (string, error) {
			switch f.String() {
			case "integration":
				return "", first
			case "integration && core":
				return "", second
			}
			return f.String(), nil
		})
	if err == nil {
		t.Fatal("failed passes were reported as success")
	}
	for _, want := range []error{first, second} {
		if !errors.Is(err, want) {
			t.Errorf("error %v does not wrap %v", err, want)
		}
	}
	// The configurations are named in the order they were given, so the same
	// input reports the same thing however the passes happened to finish.
	if a, b := strings.Index(err.Error(), "integration:"), strings.Index(err.Error(), "integration && core:"); a < 0 || b < 0 || a > b {
		t.Errorf("error %q does not report the configurations in order", err)
	}
	if got[0] != defaultTagSet {
		t.Errorf("got %v, want the successful pass kept", got)
	}
}

// TestSweepReportsAFailedPass checks that a configuration failing does not read as
// a clean result.
//
// A caller deciding whether a tree is safe has to be able to tell "nothing found"
// from "could not look", so the error propagates even though the other passes
// succeeded.
func TestSweepReportsAFailedPass(t *testing.T) {
	set := filters(t, "integration")
	boom := errors.New("could not load packages")

	got, err := sweep(context.Background(), "testing", set,
		func(_ context.Context, f tagFilter) (string, error) {
			if f.String() == "integration" {
				return "", boom
			}
			return f.String(), nil
		})
	if err == nil {
		t.Fatal("a failed pass was reported as success")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error %v does not wrap the cause", err)
	}
	// The passes that worked are still reported, so one broken configuration does
	// not lose everything.
	if got[0] != defaultTagSet {
		t.Errorf("got %v, want the successful pass kept", got)
	}
}

func TestSweepNoConfigurations(t *testing.T) {
	got, err := sweep(context.Background(), "testing", nil,
		func(context.Context, tagFilter) (string, error) {
			t.Error("a pass ran with no configurations to sweep")
			return "", nil
		})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}

// TestMergeDependents checks that the union of what every configuration reached is
// what a listing shows, and that which configurations reached a module is recorded
// alongside.
func TestMergeDependents(t *testing.T) {
	set := filters(t, "integration")
	found := []dependents{
		// The plain build.
		{"golang.org/x/sys": {"github.com/fatih/color"}},
		// Under integration, the tests pull in an AWS module as well, and x/sys
		// gains another importer.
		{
			"golang.org/x/sys":           {"golang.org/x/term"},
			"github.com/aws/aws-sdk-go2": {"example.com/m/signer"},
		},
	}

	merged, where := mergeDependents(set, found)

	// A module reached under either configuration is in the build, and its
	// importers are the union.
	want := []string{"github.com/fatih/color", "golang.org/x/term"}
	if !slices.Equal(merged["golang.org/x/sys"], want) {
		t.Errorf("x/sys importers = %v, want %v", merged["golang.org/x/sys"], want)
	}
	if got := merged["github.com/aws/aws-sdk-go2"]; len(got) != 1 {
		t.Errorf("aws importers = %v, want the one from the tagged pass", got)
	}

	// Which configurations reached each: x/sys both, the AWS module only one.
	if got := where["golang.org/x/sys"]; len(got) != 2 {
		t.Errorf("x/sys reached in %v, want both configurations", got)
	}
	if got := where["github.com/aws/aws-sdk-go2"]; !slices.Equal(got, []string{"integration"}) {
		t.Errorf("aws reached in %v, want only integration", got)
	}
}

// TestMergeAcrossTagsUnionsReachability checks that an advisory reachable under any
// configuration counts as reachable.
//
// Someone building that way runs the code, so the union is the safe reading: a
// finding merely present in one pass and reached in another is reached.
func TestMergeAcrossTagsUnionsReachability(t *testing.T) {
	found := []vulnerabilities{
		// Present but not called by a plain build.
		{"example.com/v": []vulnerability{{ID: "GO-0000-0001", FixedIn: "v1.2.0"}}},
		// Reached once the tagged files compile.
		{"example.com/v": []vulnerability{{ID: "GO-0000-0001", FixedIn: "v1.2.0", Called: true}}},
	}

	merged := mergeAcrossTags(found)
	got := merged["example.com/v"]
	if len(got) != 1 {
		t.Fatalf("got %d advisories, want the two passes merged into one", len(got))
	}
	if !got[0].Called {
		t.Error("an advisory reached under one configuration is not reported as reached")
	}
}

// TestAnnotateTagsOnlyWhenItDistinguishes checks that the configurations are
// recorded only when they differ between modules.
//
// A module every configuration reaches says nothing by saying so, and would put
// the same value on every row of a column that could have been absent.
func TestAnnotateTagsOnlyWhenItDistinguishes(t *testing.T) {
	everywhere := mustModule(t, "example.com/everywhere", "v1.0.0", "v1.1.0")
	tagged := mustModule(t, "example.com/tagged", "v1.0.0", "v1.1.0")
	unreached := mustModule(t, "example.com/unreached", "v1.0.0", "v1.1.0")

	modules := []module.Module{everywhere, tagged, unreached}
	annotateTags(modules, reachedIn{
		"example.com/everywhere": {defaultTagSet, "integration"},
		"example.com/tagged":     {"integration"},
	}, 2)

	if got := modules[0].Tags; len(got) != 0 {
		t.Errorf("a module reached everywhere carries %v, want nothing", got)
	}
	if got := modules[1].Tags; !slices.Equal(got, []string{"integration"}) {
		t.Errorf("got %v, want the one configuration that reaches it", got)
	}
	// A module nothing reached is left alone rather than marked as reached
	// nowhere, which would be a different claim.
	if got := modules[2].Tags; len(got) != 0 {
		t.Errorf("an unreached module carries %v, want nothing", got)
	}
}

// TestTagSpreadAnnotates pins how a workspace decides which configurations to
// name against a module.
//
// Members declare their own build tags, so they sweep different numbers of
// configurations. Whether naming them says anything is therefore a question about
// the member that reached the module, not about the workspace: judging against a
// workspace-wide total would label a module required only by a
// single-configuration member as reached under the plain build, which is noise.
//
// Naming the plain build on its own says nothing either, since it answers "set
// nothing", which is what an empty column already says. But that the plain build
// alone reaches a module is a fact worth reporting, so it is reported as what
// excludes the module instead: the tags every configuration that missed it sets,
// negated. A file guarded by "//go:build !integration" then reads "!integration"
// rather than "*".
func TestTagSpreadAnnotates(t *testing.T) {
	// One member's sweep: the configurations it swept, and which of them reached
	// the module, by index.
	type note struct {
		exprs   []string
		reached []int
	}
	for _, tc := range []struct {
		name  string
		notes []note
		want  []string
	}{{
		name:  "reached under every configuration of its member",
		notes: []note{{exprs: []string{"integration"}, reached: []int{0, 1}}},
		want:  nil,
	}, {
		name:  "reached under only one of two",
		notes: []note{{exprs: []string{"integration"}, reached: []int{1}}},
		want:  []string{"integration"},
	}, {
		// Judged against the workspace this would read as "only under the plain
		// build". Judged against its own member there is nothing to distinguish.
		name:  "the only configuration its member sweeps",
		notes: []note{{reached: []int{0}}},
		want:  nil,
	}, {
		// What a file guarded by "//go:build !integration" produces. Every
		// configuration that missed the module sets "integration", so that tag is
		// what excludes it, and saying so is more use than naming the plain build.
		name: "reached by the plain build alone",
		notes: []note{{
			exprs:   []string{"integration", "integration && core"},
			reached: []int{0},
		}},
		want: []string{defaultTagSet, "!integration"},
	}, {
		// The module is lost when both tags are set, not when either is. Negating
		// them separately would claim it needs neither, which is a stronger and
		// false statement.
		name: "excluded by a conjunction",
		notes: []note{{
			exprs:   []string{"integration && core"},
			reached: []int{0},
		}},
		want: []string{defaultTagSet, "!(integration && core)"},
	}, {
		// Either tag loses it, and the tags satisfying the predicate minimally are
		// only one of them, so reporting from those would drop the other.
		name: "excluded by a disjunction",
		notes: []note{{
			exprs:   []string{"integration || plugins"},
			reached: []int{0},
		}},
		want: []string{defaultTagSet, "!(integration || plugins)"},
	}, {
		// Several configurations missed it, and it takes any of them to lose it.
		name: "excluded by any of several configurations",
		notes: []note{{
			exprs:   []string{"integration", "plugins && core"},
			reached: []int{0},
		}},
		want: []string{defaultTagSet, "!(integration || (plugins && core))"},
	}, {
		// The configurations that missed it share no tag. Intersecting the tags
		// satisfying each would find nothing to blame and report silence; the
		// predicate says the true thing, which is that either one loses it.
		name: "excluded by configurations sharing no tag",
		notes: []note{{
			exprs:   []string{"integration", "plugins"},
			reached: []int{0},
		}},
		want: []string{defaultTagSet, "!(integration || plugins)"},
	}, {
		name: "one member reaches it throughout, another only when tagged",
		notes: []note{
			{exprs: []string{"integration"}, reached: []int{0, 1}},
			{exprs: []string{"plugins"}, reached: []int{1}},
		},
		want: []string{defaultTagSet, "integration", "plugins"},
	}, {
		// Nothing reached it, which is a different claim from "reached nowhere"
		// and is left for the absence of the column to make.
		name:  "unreached",
		notes: nil,
		want:  nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			const path = "example.com/m"
			spread := newTagSpread()
			for _, n := range tc.notes {
				set := filters(t, n.exprs...)
				where := reachedIn{}
				for _, at := range n.reached {
					where.note(path, set[at])
				}
				spread.add(set, where)
			}

			modules := []module.Module{mustModule(t, path, "v1.0.0", "v1.1.0")}
			spread.annotate(modules)

			if got := modules[0].Tags; !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWorthAskingOnlyOffersReachedModules pins that an upgrade is suggested only
// for a module the code imports.
//
// Upgrading one it does not would lift the vulnerable module just as well, since
// version selection does not care what is imported. But it records a requirement
// on something unrelated, which is a worse trade than upgrading the vulnerable
// module directly -- and go-mod-upgrade's own listing offered three such upgrades
// ahead of the one honest suggestion.
func TestWorthAskingOnlyOffersReachedModules(t *testing.T) {
	// The vulnerable module, and two candidates whose go.mod would lift it. Only
	// one of the two is in the build.
	sys := mustModule(t, "golang.org/x/sys", "v0.42.0", "v0.47.0")
	imported := mustModule(t, "golang.org/x/term", "v0.1.0", "v0.45.0")
	notImported := mustModule(t, "golang.org/x/net", "v0.1.0", "v0.57.0")
	// Already current, so there is no upgrade to offer whatever else is true.
	current := mustModule(t, "golang.org/x/mod", "v0.38.0", "v0.38.0")

	needed := map[string]*semver.Version{"golang.org/x/sys": fix(t, "v0.44.0")}
	reached := map[string]struct{}{
		"golang.org/x/sys":  {},
		"golang.org/x/term": {},
		"golang.org/x/mod":  {},
	}

	got := worthAsking([]module.Module{sys, imported, notImported, current}, needed, reached)
	var paths []string
	for _, c := range got {
		paths = append(paths, c.Path)
	}
	if !slices.Equal(paths, []string{"golang.org/x/term"}) {
		t.Errorf("offered %v, want only the module the code imports", paths)
	}
	// The version offered is the one the upgrade would move to, since that is
	// what decides whether it lifts anything.
	if len(got) == 1 && got[0].Version != "v0.45.0" {
		t.Errorf("version = %q, want the upgrade target", got[0].Version)
	}
}
