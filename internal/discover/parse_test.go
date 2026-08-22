package discover

import (
	"os"
	"strings"
	"testing"
)

// readFixture returns captured `go list` output.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	out, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return out
}

func TestParseModulesFixture(t *testing.T) {
	modules, err := parseModules(readFixture(t, "list-modules.json"), nil)
	if err != nil {
		t.Fatalf("parseModules: %v", err)
	}
	// The main module, the indirect one, and the one with no Update are skipped.
	if len(modules) != 3 {
		t.Fatalf("got %d modules, want 3: %+v", len(modules), modules)
	}
	if modules[0].Name != "github.com/AlecAivazis/survey/v2" {
		t.Errorf("first module = %q, want github.com/AlecAivazis/survey/v2", modules[0].Name)
	}
	if got := modules[0].From.String(); got != "2.3.7" {
		t.Errorf("first from = %q, want 2.3.7", got)
	}
	if got := modules[0].To.String(); got != "2.3.8" {
		t.Errorf("first to = %q, want 2.3.8", got)
	}
	for _, m := range modules {
		if m.Name == "github.com/mattn/go-isatty" {
			t.Error("an indirect module must not be offered for update")
		}
		if m.Name == "golang.org/x/mod" {
			t.Error("a module with no available update must not be offered")
		}
	}
}

func TestParseModulesIgnore(t *testing.T) {
	ignore, err := CompileIgnore([]string{`^github\.com/apex/`})
	if err != nil {
		t.Fatalf("CompileIgnore: %v", err)
	}
	modules, err := parseModules(readFixture(t, "list-modules.json"), ignore)
	if err != nil {
		t.Fatalf("parseModules: %v", err)
	}
	if len(modules) != 2 {
		t.Fatalf("got %d modules, want 2: %+v", len(modules), modules)
	}
	for _, m := range modules {
		if strings.Contains(m.Name, "apex") {
			t.Errorf("module %q should have been ignored", m.Name)
		}
	}
}

func TestParseModulesErrors(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantErr string
	}{
		{
			name:    "not JSON at all",
			out:     "garbage\n",
			wantErr: "error parsing go list output",
		},
		{
			name:    "a version semver rejects",
			out:     `{"Path":"example.com/a","Version":"nope","Update":{"Version":"v1.3.0"}}`,
			wantErr: "invalid semantic version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseModules([]byte(tt.out), nil)
			if err == nil {
				t.Fatalf("parseModules(%q) returned no error, want %q", tt.out, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseTools(t *testing.T) {
	tools, err := parseTools(readFixture(t, "list-tools.txt"))
	if err != nil {
		t.Fatalf("parseTools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2: %+v", len(tools), tools)
	}
	if tools[0] != (tool{path: "example.com/cmd/tool", version: "v1.2.0"}) {
		t.Errorf("first tool = %+v", tools[0])
	}
	// The one-field line is a local tool and is skipped silently.
	if tools[1] != (tool{path: "example.com/other/tool", version: "v0.4.1"}) {
		t.Errorf("second tool = %+v", tools[1])
	}
}

func TestParseToolsEmpty(t *testing.T) {
	// With no tools, `go list ... tool` exits 0 and puts its warning on
	// stderr, so stdout is empty and no error is returned. Empty result, no
	// error, and no special-case branch needed to get there.
	tools, err := parseTools([]byte(""))
	if err != nil {
		t.Fatalf("parseTools(empty): %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("got %d tools, want none: %+v", len(tools), tools)
	}
}

func TestParseToolsThreeFields(t *testing.T) {
	_, err := parseTools([]byte("a b c\n"))
	if err == nil {
		t.Fatal("parseTools(\"a b c\") returned no error, want invalid tool format")
	}
	if want := "invalid tool format: a b c"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestParseGoVersion(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    bool
		wantErr string
	}{
		{name: "current toolchain", out: "go version go1.26.3 darwin/arm64\n", want: true},
		{name: "release candidate", out: "go version go1.24rc1 linux/amd64\n", want: true},
		{
			// Pinned as-is despite being wrong: the gate is
			// `Major() >= 1 && Minor() >= 24`, so a hypothetical go2.0 —
			// minor 0 — reports tool modules as unsupported.
			name: "a hypothetical go2.0 reports unsupported",
			out:  "go version go2.0 linux/amd64\n",
			want: false,
		},
		{
			name:    "unparseable",
			out:     "garbage\n",
			wantErr: "couldn't parse go version garbage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGoVersion([]byte(tt.out))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGoVersion: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseGoVersion(%q) = %v, want %v", tt.out, got, tt.want)
			}
		})
	}
}

func TestCompileIgnore(t *testing.T) {
	res, err := CompileIgnore([]string{`^github\.com/apex/`, `log$`})
	if err != nil {
		t.Fatalf("CompileIgnore: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d patterns, want 2", len(res))
	}
	if _, err := CompileIgnore([]string{"("}); err == nil {
		t.Fatal("CompileIgnore(\"(\") returned no error, want an invalid-pattern error")
	} else if !strings.Contains(err.Error(), `invalid --ignore pattern "("`) {
		t.Errorf("error = %q, want it to name the bad pattern", err)
	}
	if res, err := CompileIgnore(nil); err != nil || len(res) != 0 {
		t.Errorf("CompileIgnore(nil) = %v, %v, want empty and no error", res, err)
	}
}

func TestShouldIgnore(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "an unanchored pattern still matches anywhere", pattern: "apex", want: true},
		{name: "the full path", pattern: `^github\.com/apex/log$`, want: true},
		{name: "an anchor that does not match", pattern: "^apex", want: false},
		{name: "a metacharacter is now a metacharacter", pattern: `apex/.*/log`, want: false},
		{name: "a character class", pattern: `github\.com/[a-z]+/log`, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ignore, err := CompileIgnore([]string{tt.pattern})
			if err != nil {
				t.Fatalf("CompileIgnore(%q): %v", tt.pattern, err)
			}
			got := shouldIgnore("github.com/apex/log", "1.9.0", "1.9.1", ignore)
			if got != tt.want {
				t.Errorf("shouldIgnore with %q = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
	if shouldIgnore("github.com/apex/log", "1.9.0", "1.9.1", nil) {
		t.Error("no patterns should ignore nothing")
	}
}
