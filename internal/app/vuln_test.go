package app

import (
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
	if !modules[0].VulnCalled {
		t.Error("x/text is reachable, want VulnCalled true")
	}
	if modules[1].VulnCalled {
		t.Error("x/sys is only present, want VulnCalled false")
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
