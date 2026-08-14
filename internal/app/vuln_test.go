package app

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// mustModule builds a module for a test, failing if either version is unusable.
func mustModule(t *testing.T, name, from, to string) module.Module {
	t.Helper()
	f, err := semver.NewVersion(from)
	if err != nil {
		t.Fatalf("parsing %q: %v", from, err)
	}
	v, err := semver.NewVersion(to)
	if err != nil {
		t.Fatalf("parsing %q: %v", to, err)
	}
	return module.Module{Name: name, From: f, To: v}
}

// A govulncheck stream reporting one advisory twice: once naming only the
// module, and once naming the package through which it is reached.
const vulnStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"SBOM":{"go_version":"go1.26.5"}}
{"progress":{"message":"Scanning your code and 60 packages across 12 dependent modules for known vulnerabilities..."}}
{"osv":{"id":"GO-2026-5970","aliases":["CVE-2026-56852"],"summary":"Infinite loop on invalid input in golang.org/x/text","database_specific":{"url":"https://pkg.go.dev/vuln/GO-2026-5970"}}}
{"osv":{"id":"GO-2026-5024","aliases":["CVE-2026-5024","GHSA-xxxx-yyyy-zzzz"],"summary":"Integer overflow in golang.org/x/sys/windows","database_specific":{"url":"https://pkg.go.dev/vuln/GO-2026-5024"}}}
{"finding":{"osv":"GO-2026-5970","fixed_version":"v0.39.0","trace":[{"module":"golang.org/x/text","version":"v0.4.0"}]}}
{"finding":{"osv":"GO-2026-5970","fixed_version":"v0.39.0","trace":[{"module":"golang.org/x/text","version":"v0.4.0","package":"golang.org/x/text/unicode/norm"}]}}
{"finding":{"osv":"GO-2026-5024","fixed_version":"v0.44.0","trace":[{"module":"golang.org/x/sys","version":"v0.42.0"}]}}
`

// TestGoEnvDropsUnpermitted checks that a variable outside the allow-list does not reach
// the toolchain.
//
// Anything able to change what the toolchain answers has to be either excluded or keyed.
// Passing the ambient environment through would mean keying the ambient environment, which
// cannot be done: it holds values that differ between two runs that should share an answer.
func TestGoEnvDropsUnpermitted(t *testing.T) {
	got := goEnv([]string{
		"GOPROXY=https://example.test",
		"SOMETHING_ELSE=tainted",
		"GOFLAGS=-mod=mod",
	})

	if slices.Contains(got, "SOMETHING_ELSE=tainted") {
		t.Error("an unpermitted variable reached the toolchain")
	}
	for _, want := range []string{"GOPROXY=https://example.test", "GOFLAGS=-mod=mod"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q did not survive, got %q", want, got)
		}
	}
}

// TestGoEnvKeepsAnEmptyValue checks that a permitted variable set to nothing is passed on.
//
// "GOPROXY=" is an empty proxy list rather than the default, so dropping it because it looks
// like nothing would quietly change where modules come from.
func TestGoEnvKeepsAnEmptyValue(t *testing.T) {
	got := goEnv([]string{"GOFLAGS="})

	if !slices.Contains(got, "GOFLAGS=") {
		t.Errorf("an empty permitted value was dropped, got %q", got)
	}
}

// TestKeyedEnvCoversEveryPermittedVariable checks the key names the whole allow-list.
//
// The passthrough and the key are the same set by construction, and the point of that is
// that they cannot drift: a variable admitted to the toolchain without reaching the key
// could change an answer that a later run is then handed.
func TestKeyedEnvCoversEveryPermittedVariable(t *testing.T) {
	got := keyedEnv()

	if len(got) != len(permittedEnv) {
		t.Errorf("keyed %d variables, want one per permitted variable (%d)", len(got), len(permittedEnv))
	}
	for k := range permittedEnv {
		found := false
		for _, entry := range got {
			if name, _, _ := strings.Cut(entry, "\x00"); name == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is permitted but does not reach the key", k)
		}
	}
}

// TestKeyedEnvSeparatesUnsetFromEmpty checks the three states a variable can be in are
// three different keys.
//
// The toolchain reads unset, empty and set differently, so a key that conflated any two
// would hand a run the answer gathered under one of the others.
func TestKeyedEnvSeparatesUnsetFromEmpty(t *testing.T) {
	entry := func() string {
		t.Helper()
		for _, e := range keyedEnv() {
			if name, rest, _ := strings.Cut(e, "\x00"); name == "GOFLAGS" {
				return rest
			}
		}
		t.Fatal("GOFLAGS did not reach the key")
		return ""
	}

	os.Unsetenv("GOFLAGS")
	unset := entry()

	t.Setenv("GOFLAGS", "")
	empty := entry()

	t.Setenv("GOFLAGS", "-mod=mod")
	set := entry()

	if unset == empty {
		t.Errorf("unset and empty key alike as %q, so clearing GOFLAGS reuses the older answer", unset)
	}
	if empty == set {
		t.Errorf("empty and set key alike as %q", empty)
	}
}

// TestScanEnvDisablesWorkspace checks a scan resolves the module it was pointed at rather
// than the workspace containing it.
//
// The scan is the one invocation that did not disable workspace mode, so it read versions
// the rest of the run never reported on: a member requiring x/text v0.3.0 beside one pinning
// v0.40.0 was listed as upgradable from v0.3.0 while the scan read v0.40.0.
func TestScanEnvDisablesWorkspace(t *testing.T) {
	t.Setenv("GOWORK", "")

	got, found := gowork(scanEnv())
	if !found {
		t.Fatal("the scan sets no GOWORK, so it would resolve through the workspace")
	}
	if got != "off" {
		t.Errorf("GOWORK=%q, want \"off\"", got)
	}
}

// gowork reports the GOWORK the given environment settles on, and whether it names one.
//
// The last value for a key wins, as in os/exec, so the search runs backwards.
func gowork(env []string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		if after, ok := strings.CutPrefix(env[i], "GOWORK="); ok {
			return after, true
		}
	}
	return "", false
}

// TestNoWorkspaceDisablesWorkspace checks that a command resolves the module in its own
// directory rather than the workspace containing it.
//
// A listing must report what the module's own go.mod requires. Left in workspace mode it
// would resolve through workspace-wide MVS and report on a sibling's pinned version -- so
// the tool could name an upgrade for a version it never scanned, and call a module clean
// because a neighbour happens to require a fixed one.
func TestNoWorkspaceDisablesWorkspace(t *testing.T) {
	t.Setenv("GOWORK", "")

	cmd := exec.Command("go", "list")
	noWorkspace(cmd)

	got, found := gowork(cmd.Env)
	if !found {
		t.Fatal("no GOWORK set, so the command would resolve through the workspace")
	}
	if got != "off" {
		t.Errorf("GOWORK=%q, want \"off\"", got)
	}
}

// TestNoWorkspaceKeepsAnExplicitGowork checks that a GOWORK the caller set is left alone.
//
// Disabling the workspace is this tool's default rather than a correction: someone naming a
// particular work file has been more specific than the default, and overruling them would
// leave no way to ask for it.
func TestNoWorkspaceKeepsAnExplicitGowork(t *testing.T) {
	t.Setenv("GOWORK", "/elsewhere/go.work")

	cmd := exec.Command("go", "list")
	noWorkspace(cmd)

	got, found := gowork(cmd.Env)
	if !found {
		t.Fatal("the explicit GOWORK went missing from the environment")
	}
	if got != "/elsewhere/go.work" {
		t.Errorf("GOWORK=%q, want the caller's %q", got, "/elsewhere/go.work")
	}
}

// TestNoWorkspaceReflectsTheCommandDir checks the child is told where it actually runs.
//
// cmd.Environ() derives PWD from cmd.Dir, which os.Environ() cannot do: building on the
// process environment would hand the child this process's PWD while it ran somewhere else.
func TestNoWorkspaceReflectsTheCommandDir(t *testing.T) {
	t.Setenv("GOWORK", "")
	dir := t.TempDir()

	cmd := exec.Command("go", "list")
	cmd.Dir = dir
	noWorkspace(cmd)

	// Only meaningful when the parent has a PWD for cmd.Environ() to rewrite.
	if os.Getenv("PWD") == "" {
		t.Skip("no PWD in the environment to rewrite")
	}
	var pwd string
	for i := len(cmd.Env) - 1; i >= 0; i-- {
		if after, ok := strings.CutPrefix(cmd.Env[i], "PWD="); ok {
			pwd = after
			break
		}
	}
	if pwd != dir {
		t.Errorf("PWD=%q, want the command's dir %q", pwd, dir)
	}
}

func TestParseVulnerabilities(t *testing.T) {
	vulns, err := parseVulnerabilities([]byte(vulnStream))
	if err != nil {
		t.Fatalf("parseVulnerabilities: %v", err)
	}

	// The two findings for one advisory describe the same problem, so they
	// are reported once.
	text := vulns["golang.org/x/text"]
	if len(text) != 1 {
		t.Fatalf("got %d advisories for x/text, want 1", len(text))
	}
	if !text[0].Called {
		t.Error("a trace naming a package means the code is reachable, want Called true")
	}
	if got, want := text[0].FixedIn, "v0.39.0"; got != want {
		t.Errorf("FixedIn = %q, want %q", got, want)
	}
	if got, want := text[0].URL, "https://pkg.go.dev/vuln/GO-2026-5970"; got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}

	// A trace naming only the module means the vulnerable code is present
	// but not reached.
	sys := vulns["golang.org/x/sys"]
	if len(sys) != 1 {
		t.Fatalf("got %d advisories for x/sys, want 1", len(sys))
	}
	if sys[0].Called {
		t.Error("a trace naming no package means the code is not reached, want Called false")
	}
}

// A stdlib advisory as govulncheck really reports it, taken from a scan of
// opensearch-go/cmd/osgen under Go 1.25.9.
//
// The trace is ordered from the vulnerable symbol outwards: crypto/tls at the
// front, then the stdlib and module frames that call it, ending at main. Only
// the first element names what is actually vulnerable.
const stdlibStream = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2026-5856","aliases":["CVE-2026-42505"],"summary":"Encrypted Client Hello privacy leak in crypto/tls","database_specific":{"url":"https://pkg.go.dev/vuln/GO-2026-5856"}}}
{"finding":{"osv":"GO-2026-5856","fixed_version":"v1.25.12","trace":[
  {"module":"stdlib","version":"v1.25.9","package":"crypto/tls"},
  {"module":"stdlib","version":"v1.25.9","package":"net/http"},
  {"module":"github.com/getkin/kin-openapi","version":"v0.145.0","package":"github.com/getkin/kin-openapi/openapi3"},
  {"module":"github.com/opensearch-project/opensearch-go/v5/cmd/osgen","version":"v5.0.0","package":"github.com/opensearch-project/opensearch-go/v5/cmd/osgen"}
]}}
`

// TestParseVulnerabilitiesBlamesTheVulnerableModule pins that an advisory is
// attributed to the module carrying the vulnerable code, not to everything on
// the path that reaches it.
//
// govulncheck orders a trace from the vulnerable symbol outwards, so trace[0] is
// the only element naming what is defective; the rest are callers. Attributing
// to all of them flagged kin-openapi for a crypto/tls bug and told the reader to
// upgrade a module that was already at its newest version -- a fix that could
// not possibly work, since the defect was in the toolchain.
func TestParseVulnerabilitiesBlamesTheVulnerableModule(t *testing.T) {
	vulns, err := parseVulnerabilities([]byte(stdlibStream))
	if err != nil {
		t.Fatalf("parseVulnerabilities: %v", err)
	}

	// The vulnerability is in the standard library, so that is what carries it.
	std := vulns[stdlibModule]
	if len(std) != 1 {
		t.Fatalf("got %d advisories for the standard library, want 1", len(std))
	}
	if !std[0].Called {
		t.Error("the trace names a package, so the code is reached; want Called true")
	}
	if got, want := std[0].FixedIn, "v1.25.12"; got != want {
		t.Errorf("FixedIn = %q, want %q", got, want)
	}

	// Nothing on the call path is blamed for a defect it does not have.
	for _, caller := range []string{
		"github.com/getkin/kin-openapi",
		"github.com/opensearch-project/opensearch-go/v5/cmd/osgen",
		"net/http",
	} {
		if got := vulns[caller]; len(got) != 0 {
			t.Errorf("%s was blamed for %d advisories, want none: it calls the "+
				"vulnerable code rather than containing it", caller, len(got))
		}
	}
}

func TestVulnerabilityCVE(t *testing.T) {
	cases := []struct {
		name    string
		aliases []string
		want    string
	}{
		{
			name:    "prefers a CVE number",
			aliases: []string{"GHSA-xxxx-yyyy-zzzz", "CVE-2026-56852"},
			want:    "CVE-2026-56852",
		},
		{
			// The Go database always assigns its own identifier, so it can
			// stand in when no CVE has been issued.
			name:    "falls back to the Go identifier",
			aliases: []string{"GHSA-xxxx-yyyy-zzzz"},
			want:    "GO-2026-5970",
		},
		{
			name:    "no aliases at all",
			aliases: nil,
			want:    "GO-2026-5970",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := vulnerability{ID: "GO-2026-5970", Aliases: c.aliases}
			if got := v.CVE(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseVulnerabilitiesOrder checks that a reachable advisory is reported
// before one that is merely present, so the pressing entry survives truncation.
func TestParseVulnerabilitiesOrder(t *testing.T) {
	stream := `
{"osv":{"id":"GO-0000-0002","aliases":["CVE-0000-0002"]}}
{"osv":{"id":"GO-0000-0001","aliases":["CVE-0000-0001"]}}
{"finding":{"osv":"GO-0000-0001","trace":[{"module":"example.com/m","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-0000-0002","trace":[{"module":"example.com/m","version":"v1.0.0","package":"example.com/m/pkg"}]}}
`
	vulns, err := parseVulnerabilities([]byte(stream))
	if err != nil {
		t.Fatalf("parseVulnerabilities: %v", err)
	}
	got := vulns["example.com/m"]
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want 2", len(got))
	}
	if !got[0].Called {
		t.Errorf("got %s first, want the reachable advisory", got[0].ID)
	}
}

func TestParseVulnerabilitiesNone(t *testing.T) {
	// A scan finding nothing still reports its configuration.
	vulns, err := parseVulnerabilities([]byte(`{"config":{"scanner_name":"govulncheck"}}`))
	if err != nil {
		t.Fatalf("parseVulnerabilities: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("got %v, want no vulnerabilities", vulns)
	}
}

func TestParseVulnerabilitiesInvalid(t *testing.T) {
	if _, err := parseVulnerabilities([]byte("{not json")); err == nil {
		t.Error("expected an error for malformed input")
	}
}

func TestAnnotateVulns(t *testing.T) {
	modules := []module.Module{
		mustModule(t, "golang.org/x/text", "v0.4.0", "v0.40.0"),
		mustModule(t, "golang.org/x/sys", "v0.42.0", "v0.47.0"),
		mustModule(t, "example.com/clean", "v1.0.0", "v1.0.1"),
	}
	vulns, err := parseVulnerabilities([]byte(vulnStream))
	if err != nil {
		t.Fatalf("parseVulnerabilities: %v", err)
	}

	annotateVulns(modules, vulns)

	if got, want := modules[0].Vulns, []string{"CVE-2026-56852"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("x/text Vulns = %v, want %v", got, want)
	}
	if modules[0].Reachable != 1 {
		t.Errorf("x/text Reachable = %d, want 1", modules[0].Reachable)
	}
	if modules[1].Reachable != 0 {
		t.Errorf("x/sys is only present, Reachable = %d, want 0", modules[1].Reachable)
	}
	// A module with no advisory is left alone.
	if len(modules[2].Vulns) != 0 {
		t.Errorf("example.com/clean Vulns = %v, want none", modules[2].Vulns)
	}
}

// TestMergeVulnsReachability checks that an advisory reported by several
// workspace members is recorded once, and counts as reachable if any one of
// them reaches the vulnerable code.
func TestMergeVulnsReachability(t *testing.T) {
	present := vulnerabilities{"example.com/m": {{ID: "GO-0000-0001"}}}
	reached := vulnerabilities{"example.com/m": {{ID: "GO-0000-0001", Called: true}}}

	// The order the members are scanned in must not change the outcome.
	for _, c := range []struct {
		name  string
		first vulnerabilities
		then  vulnerabilities
	}{
		{"reachable last", present, reached},
		{"reachable first", reached, present},
	} {
		t.Run(c.name, func(t *testing.T) {
			into := vulnerabilities{}
			mergeVulns(into, c.first)
			mergeVulns(into, c.then)

			got := into["example.com/m"]
			if len(got) != 1 {
				t.Fatalf("got %d advisories, want the one recorded once", len(got))
			}
			if !got[0].Called {
				t.Error("want Called true when any member reaches the code")
			}
		})
	}
}

func TestMergeVulnsDistinctAdvisories(t *testing.T) {
	into := vulnerabilities{}
	mergeVulns(into, vulnerabilities{"example.com/m": {{ID: "GO-0000-0001"}}})
	mergeVulns(into, vulnerabilities{"example.com/m": {{ID: "GO-0000-0002"}}})
	mergeVulns(into, vulnerabilities{"example.com/other": {{ID: "GO-0000-0001"}}})

	if got := into["example.com/m"]; len(got) != 2 {
		t.Errorf("got %d advisories for m, want both kept", len(got))
	}
	if got := into["example.com/other"]; len(got) != 1 {
		t.Errorf("got %d advisories for other, want 1", len(got))
	}
}

// TestToolchainModule pins how a standard library advisory is reported, since it
// has no go.mod entry to attach to and so needs a row of its own.
func TestToolchainModule(t *testing.T) {
	vulns := vulnerabilities{
		stdlibModule: []vulnerability{
			// Two advisories fixed in different releases. One toolchain upgrade
			// resolves both, so the newer fix is the one to report.
			{ID: "GO-2026-4970", Aliases: []string{"CVE-2026-39822"}, FixedIn: "v1.25.12", Called: true},
			{ID: "GO-2026-5037", Aliases: []string{"CVE-2026-40001"}, FixedIn: "v1.25.11"},
		},
	}

	got, ok := toolchainModule("1.25.9", vulns, nil)
	if !ok {
		t.Fatal("no toolchain row for a standard library advisory, want one")
	}
	if got.Name != ToolchainName {
		t.Errorf("Name = %q, want %q", got.Name, ToolchainName)
	}
	if from := got.From.String(); from != "1.25.9" {
		t.Errorf("From = %q, want the declared version", from)
	}
	// The newest fix governs: upgrading to it resolves every advisory below it.
	if to := got.To.String(); to != "1.25.12" {
		t.Errorf("To = %q, want the newest fix", to)
	}
	if len(got.Vulns) != 2 {
		t.Errorf("Vulns = %v, want both advisories", got.Vulns)
	}
	if got.Reachable != 1 {
		t.Errorf("Reachable = %d, want 1", got.Reachable)
	}

	// The row is never offered for upgrade: "go get" cannot move the go
	// directive, so an upgrade would silently do nothing.
	if left := upgradable([]module.Module{got}, false); len(left) != 0 {
		t.Errorf("got %d upgradable, want the toolchain row withheld", len(left))
	}
}

// TestToolchainModuleAbsent covers the cases where there is nothing to report,
// so an ordinary run gains no spurious row.
func TestToolchainModuleAbsent(t *testing.T) {
	cases := []struct {
		name    string
		version string
		vulns   vulnerabilities
	}{
		{
			name:    "no standard library advisory",
			version: "1.25.9",
			vulns:   vulnerabilities{"golang.org/x/text": []vulnerability{{ID: "GO-2026-5970"}}},
		},
		{
			// Without a go directive there is nothing to measure against.
			name:    "no declared version",
			version: "",
			vulns:   vulnerabilities{stdlibModule: []vulnerability{{ID: "GO-2026-4970"}}},
		},
		{
			// A go directive that is not a version is not worth guessing at.
			name:    "unparseable version",
			version: "not-a-version",
			vulns:   vulnerabilities{stdlibModule: []vulnerability{{ID: "GO-2026-4970"}}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := toolchainModule(c.version, c.vulns, nil); ok {
				t.Error("got a toolchain row, want none")
			}
		})
	}
}

// TestToolchainModuleAlreadyPatched checks that a toolchain newer than every fix
// reports the advisories without inventing an upgrade, which is what keeps the
// row out of a listing filtered by the default --show.
//
// No ranges are given, so nothing says whether the declared version is covered
// and every advisory the scan found is reported.
func TestToolchainModuleAlreadyPatched(t *testing.T) {
	vulns := vulnerabilities{
		stdlibModule: []vulnerability{{ID: "GO-2026-4970", FixedIn: "v1.25.12"}},
	}
	got, ok := toolchainModule("1.26.5", vulns, nil)
	if !ok {
		t.Fatal("want the advisory still reported")
	}
	if !got.From.Equal(got.To) {
		t.Errorf("From %s, To %s, want them equal when already patched", got.From, got.To)
	}
}

// TestToolchainModuleMeasuresTheDeclaredVersion pins which findings reach the row.
//
// A scan reports the fixed version for the line it ran under, so a fix backported to
// 1.25.12 and 1.26.5 arrives as v1.26.5 alone and would condemn a patched 1.25.12.
func TestToolchainModuleMeasuresTheDeclaredVersion(t *testing.T) {
	// The bounds the database publishes: "0" for the beginning of time and the
	// "1.26.0-0" sentinel opening a line. GO-2026-4970 is fixed at 1.25.12 and 1.26.5,
	// GO-2026-5037 covers the 1.25 line only, GO-2026-5100 at 1.25.13, GO-2026-5200 a
	// later line than either, GO-2026-5300 nothing.
	covers := advisoryWindows{
		"GO-2026-4970": {
			{From: &semver.Version{}, To: semver.MustParse("1.25.12")},
			{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.5")},
		},
		"GO-2026-5037": {
			{From: &semver.Version{}, To: semver.MustParse("1.25.11")},
		},
		"GO-2026-5100": {
			{From: &semver.Version{}, To: semver.MustParse("1.25.13")},
			{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.6")},
		},
		"GO-2026-5200": {
			{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.4")},
		},
		"GO-2026-5300": {
			{From: &semver.Version{}},
		},
	}
	backported := vulnerability{ID: "GO-2026-4970", Aliases: []string{"CVE-2026-39822"}, FixedIn: "v1.26.5", Called: true}
	oneLine := vulnerability{ID: "GO-2026-5037", Aliases: []string{"CVE-2026-40001"}, FixedIn: "v1.25.11"}
	laterFix := vulnerability{ID: "GO-2026-5100", Aliases: []string{"CVE-2026-40002"}, FixedIn: "v1.26.6"}
	laterLine := vulnerability{ID: "GO-2026-5200", Aliases: []string{"CVE-2026-40003"}, FixedIn: "v1.26.4"}
	unfixed := vulnerability{ID: "GO-2026-5300", Aliases: []string{"CVE-2026-40004"}}
	unknown := vulnerability{ID: "GO-2026-9999", Aliases: []string{"CVE-2026-99999"}, FixedIn: "v1.26.5"}

	cases := []struct {
		name      string
		declared  string
		found     []vulnerability
		wantRow   bool
		want      []string
		wantTo    string
		reachable int
	}{
		{
			// The declaration the scan's own fixed version would condemn.
			name:     "declared version carries the backported fix",
			declared: "1.25.12",
			found:    []vulnerability{backported},
			wantRow:  false,
		},
		{
			// The 1.25 fix, not the 1.26.5 the scan named.
			name:      "declared version sits inside the range",
			declared:  "1.25.9",
			found:     []vulnerability{backported},
			wantRow:   true,
			want:      []string{"CVE-2026-39822"},
			wantTo:    "1.25.12",
			reachable: 1,
		},
		{
			name:      "one advisory covers the declaration and one does not",
			declared:  "1.25.11",
			found:     []vulnerability{backported, oneLine},
			wantRow:   true,
			want:      []string{"CVE-2026-39822"},
			wantTo:    "1.25.12",
			reachable: 1,
		},
		{
			// A cleared advisory must not raise the row's fix.
			name:     "cleared advisory holds the newest fix",
			declared: "1.25.12",
			found:    []vulnerability{backported, laterFix},
			wantRow:  true,
			want:     []string{"CVE-2026-40002"},
			wantTo:   "1.25.13",
		},
		{
			// A floor says nothing about the toolchain honouring it: 1.24.0 can be
			// built by an affected 1.26.2.
			name:     "declared version predates the affected line",
			declared: "1.24.0",
			found:    []vulnerability{laterLine},
			wantRow:  true,
			want:     []string{"CVE-2026-40003"},
			wantTo:   "1.26.4",
		},
		{
			// Nothing fixes it yet, so no upgrade is named.
			name:     "advisory with no fix published",
			declared: "1.25.12",
			found:    []vulnerability{unfixed},
			wantRow:  true,
			want:     []string{"CVE-2026-40004"},
			wantTo:   "1.25.12",
		},
		{
			// Unknown to the database, so a partial cache narrows nothing.
			name:     "advisory absent from the ranges",
			declared: "1.26.5",
			found:    []vulnerability{unknown},
			wantRow:  true,
			want:     []string{"CVE-2026-99999"},
			wantTo:   "1.26.5",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := toolchainModule(c.declared, vulnerabilities{stdlibModule: c.found}, covers)
			if ok != c.wantRow {
				t.Fatalf("row reported = %t, want %t", ok, c.wantRow)
			}
			if !ok {
				return
			}
			if !slices.Equal(got.Vulns, c.want) {
				t.Errorf("Vulns = %v, want %v", got.Vulns, c.want)
			}
			if to := got.To.String(); to != c.wantTo {
				t.Errorf("To = %q, want %q", to, c.wantTo)
			}
			if got.Reachable != c.reachable {
				t.Errorf("Reachable = %d, want %d", got.Reachable, c.reachable)
			}
		})
	}
}
