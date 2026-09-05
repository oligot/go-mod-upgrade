package discover

import (
	"testing"
)

func TestFilterPrivateModules(t *testing.T) {
	deps := map[string]string{
		"corp.internal/foo":       "v1.0.0",
		"git.corp.example.com/db": "v2.1.0",
		"github.com/foo/bar":      "v1.0.0",
	}

	got := filterPrivateModules(deps, "corp.internal,*.corp.example.com")
	if _, ok := got["corp.internal/foo"]; ok {
		t.Error("corp.internal/foo must be filtered by GOPRIVATE")
	}
	if _, ok := got["git.corp.example.com/db"]; ok {
		t.Error("git.corp.example.com/db must be filtered by GOPRIVATE glob")
	}
	if _, ok := got["github.com/foo/bar"]; !ok {
		t.Error("github.com/foo/bar must not be filtered")
	}

	got = filterPrivateModules(deps, "")
	if len(got) != 3 {
		t.Errorf("empty GOPRIVATE must filter nothing, got %d entries", len(got))
	}
}

func TestParseDirectDependencies(t *testing.T) {
	// `go list -m -f ...` emits an empty line for every module the template
	// filters out, which is most of them.
	out := []byte("github.com/foo/bar v1.2.3\n\n\ngithub.com/baz/qux v0.4.0\n\n")
	got := parseDirectDependencies(out)
	if len(got) != 2 {
		t.Fatalf("parseDirectDependencies() returned %d entries, want 2: %v", len(got), got)
	}
	if got["github.com/foo/bar"] != "v1.2.3" {
		t.Errorf("github.com/foo/bar = %q, want v1.2.3", got["github.com/foo/bar"])
	}
	if got["github.com/baz/qux"] != "v0.4.0" {
		t.Errorf("github.com/baz/qux = %q, want v0.4.0", got["github.com/baz/qux"])
	}
}
