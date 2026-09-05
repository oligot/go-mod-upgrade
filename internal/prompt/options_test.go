package prompt

import (
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// mod builds a Module from version strings, failing the test on bad input.
func mod(t *testing.T, name, from, to string) module.Module {
	t.Helper()
	fromVersion, err := semver.NewVersion(from)
	if err != nil {
		t.Fatalf("bad from version %q: %v", from, err)
	}
	toVersion, err := semver.NewVersion(to)
	if err != nil {
		t.Fatalf("bad to version %q: %v", to, err)
	}
	return module.Module{Name: name, From: fromVersion, To: toVersion}
}

func TestBuildOptions(t *testing.T) {
	// The formatters emit ANSI colour codes; switch them off so the labels
	// are comparable as plain text.
	color.NoColor = true

	modules := []module.Module{
		mod(t, "a", "1.0.0", "1.0.1"),
		mod(t, "bbbb", "10.20.30", "10.20.31"),
	}
	want := []string{
		"a    1.0.0    -> 1.0.1",
		"bbbb 10.20.30 -> 10.20.31",
	}

	options := buildOptions(modules)
	if len(options) != len(modules) {
		t.Fatalf("got %d options, want %d", len(options), len(modules))
	}
	for i, option := range options {
		if option.Key != want[i] {
			t.Errorf("option %d key = %q, want %q", i, option.Key, want[i])
		}
		if option.Value != modules[i] {
			t.Errorf("option %d value = %+v, want %+v", i, option.Value, modules[i])
		}
	}
}

func TestBuildOptionsAlignsArrows(t *testing.T) {
	color.NoColor = true

	// Names and current versions of differing lengths must still produce
	// arrows in the same column, so the versions read as columns.
	options := buildOptions([]module.Module{
		mod(t, "a", "1.0.0", "1.0.1"),
		mod(t, "a/much/longer/name", "10.20.30", "10.20.31"),
		mod(t, "middling", "2.0.0", "3.0.0"),
	})

	want := strings.Index(options[0].Key, "->")
	if want < 0 {
		t.Fatalf("no arrow in %q", options[0].Key)
	}
	for i, option := range options[1:] {
		if got := strings.Index(option.Key, "->"); got != want {
			t.Errorf("option %d arrow at column %d, want %d (%q)", i+1, got, want, option.Key)
		}
	}
}

func TestBuildOptionsEmpty(t *testing.T) {
	if options := buildOptions(nil); len(options) != 0 {
		t.Errorf("got %d options, want 0", len(options))
	}
}
