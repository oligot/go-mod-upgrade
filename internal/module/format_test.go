package module

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWritePolicyDefersToGoMod checks that a generated policy names the modules
// and leaves the versions to go.mod, so the two cannot drift apart.
func TestWritePolicyDefersToGoMod(t *testing.T) {
	mods := []Module{
		mod(t, "golang.org/x/text", "v0.4.0", "v0.40.0", true),
		mod(t, "github.com/urfave/cli/v3", "v3.9.0", "v3.10.1", false),
	}

	var buf strings.Builder
	if err := WritePolicy(&buf, mods); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}

	var got struct {
		Modules map[string]map[string]string `json:"modules"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Modules) != len(mods) {
		t.Fatalf("got %d modules, want %d", len(got.Modules), len(mods))
	}
	for _, m := range mods {
		entry, ok := got.Modules[m.Name]
		if !ok {
			t.Errorf("%s is missing", m.Name)
			continue
		}
		// No version is recorded: go.mod already holds it.
		if entry["allow"] != "go.mod" {
			t.Errorf("%s allows %q, want %q", m.Name, entry["allow"], "go.mod")
		}
	}
}

// TestWritePolicyIsStable checks that regenerating produces the same bytes, so
// a checked-in policy does not churn in review.
func TestWritePolicyIsStable(t *testing.T) {
	mods := []Module{
		mod(t, "example.com/b", "v1.0.0", "v1.0.1", false),
		mod(t, "example.com/a", "v1.0.0", "v1.0.1", false),
	}
	var first, second strings.Builder
	if err := WritePolicy(&first, mods); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	// Reversing the input must not change the output, since a map has no order
	// and the encoder sorts its keys.
	if err := WritePolicy(&second, []Module{mods[1], mods[0]}); err != nil {
		t.Fatalf("WritePolicy: %v", err)
	}
	if first.String() != second.String() {
		t.Errorf("output depends on input order:\n%s\n---\n%s", first.String(), second.String())
	}
}

// TestWriteJSONReportsFindings checks that the report carries what another tool
// would need, including the reachability that distinguishes an advisory to act
// on from one to note.
func TestWriteJSONReportsFindings(t *testing.T) {
	m := mod(t, "golang.org/x/text", "v0.4.0", "v0.40.0", true)
	m.Vulns = []string{"CVE-2026-56852"}
	m.Reachable = 1
	m.RequiredBy = []string{"github.com/AlecAivazis/survey/v2"}

	var buf strings.Builder
	if err := WriteJSON(&buf, []Module{m}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got struct {
		Modules map[string]struct {
			Version    string   `json:"version"`
			Update     string   `json:"update"`
			Indirect   bool     `json:"indirect"`
			Vulns      []string `json:"vulns"`
			Reachable  int      `json:"reachable"`
			RequiredBy []string `json:"required_by"`
		} `json:"modules"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	entry := got.Modules["golang.org/x/text"]
	if entry.Version != "v0.4.0" || entry.Update != "v0.40.0" {
		t.Errorf("got %s -> %s, want v0.4.0 -> v0.40.0", entry.Version, entry.Update)
	}
	if !entry.Indirect {
		t.Error("indirect was not reported")
	}
	if entry.Reachable != 1 {
		t.Errorf("reachable = %d, want 1", entry.Reachable)
	}
	if len(entry.Vulns) != 1 || entry.Vulns[0] != "CVE-2026-56852" {
		t.Errorf("vulns = %v, want the advisory", entry.Vulns)
	}
	if len(entry.RequiredBy) != 1 {
		t.Errorf("required_by = %v, want what pulls it in", entry.RequiredBy)
	}
}

// TestWriteJSONOmitsAbsentUpdate checks that a module already at its newest
// version reports no update, rather than one equal to its current version.
func TestWriteJSONOmitsAbsentUpdate(t *testing.T) {
	var buf strings.Builder
	if err := WriteJSON(&buf, []Module{mod(t, "example.com/m", "v1.0.0", "v1.0.0", false)}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(buf.String(), "update") {
		t.Errorf("an update was reported for a current module:\n%s", buf.String())
	}
}

func TestValidFormat(t *testing.T) {
	for _, name := range FormatNames() {
		if err := ValidFormat(name); err != nil {
			t.Errorf("ValidFormat(%q) = %v, want nil", name, err)
		}
	}
	err := ValidFormat("yaml")
	if err == nil {
		t.Fatal("expected an error for an unknown format")
	}
	for _, name := range FormatNames() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not mention %q", err, name)
		}
	}
}
