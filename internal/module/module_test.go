package module

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
)

// mod builds a Module from version strings, failing the test on bad input.
func mod(t *testing.T, name, from, to string) Module {
	t.Helper()
	fromVersion, err := semver.NewVersion(from)
	if err != nil {
		t.Fatalf("bad from version %q: %v", from, err)
	}
	toVersion, err := semver.NewVersion(to)
	if err != nil {
		t.Fatalf("bad to version %q: %v", to, err)
	}
	return Module{Name: name, From: fromVersion, To: toVersion}
}

func TestPadRight(t *testing.T) {
	if got := padRight("ab", 5); got != "ab   " {
		t.Errorf("padRight(%q, 5) = %q, want %q", "ab", got, "ab   ")
	}
	if got := padRight("abcdef", 3); got != "abcdef" {
		t.Errorf("padRight(%q, 3) = %q, want it returned unchanged", "abcdef", got)
	}
}

func TestMaxWidths(t *testing.T) {
	tests := []struct {
		name     string
		modules  func(t *testing.T) []Module
		wantName int
		wantFrom int
	}{
		{
			name:    "no modules",
			modules: func(t *testing.T) []Module { return nil },
		},
		{
			name: "widest name and widest version come from different modules",
			modules: func(t *testing.T) []Module {
				return []Module{
					mod(t, "github.com/a/very/long/name", "1.0.0", "1.0.1"),
					mod(t, "short", "10.20.30", "10.20.31"),
				}
			},
			wantName: 27,
			wantFrom: 8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, from := MaxWidths(tt.modules(t))
			if name != tt.wantName {
				t.Errorf("name width = %d, want %d", name, tt.wantName)
			}
			if from != tt.wantFrom {
				t.Errorf("from width = %d, want %d", from, tt.wantFrom)
			}
		})
	}
}

func TestFormatName(t *testing.T) {
	// fatih/color drops the escape codes when stdout is not a TTY, which is
	// exactly the case under `go test`. Without this the assertions below
	// would compare bare strings and pin nothing.
	color.NoColor = false

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		// A zero major wins over every other branch: this is a minor bump,
		// but it renders red rather than yellow.
		{name: "zero major beats a minor bump", from: "0.1.0", to: "0.2.0", want: "\x1b[31ma   \x1b[0m"},
		{name: "minor bump is yellow", from: "1.2.3", to: "1.3.0", want: "\x1b[33ma   \x1b[0m"},
		{name: "patch bump is green", from: "1.2.3", to: "1.2.4", want: "\x1b[32ma   \x1b[0m"},
		{name: "no change is white", from: "1.2.3", to: "1.2.3", want: "\x1b[37ma   \x1b[0m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mod(t, "a", tt.from, tt.to)
			if got := m.FormatName(4); got != tt.want {
				t.Errorf("FormatName(4) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatFrom(t *testing.T) {
	color.NoColor = false

	m := mod(t, "a", "1.2.3", "1.2.4")
	if got, want := m.FormatFrom(8), "\x1b[34m1.2.3   \x1b[0m"; got != want {
		t.Errorf("FormatFrom(8) = %q, want %q", got, want)
	}
	// Padding never truncates: the version is longer than the column.
	long := mod(t, "a", "1.2.3-alpha", "1.2.3-beta")
	if got, want := long.FormatFrom(8), "\x1b[34m1.2.3-alpha\x1b[0m"; got != want {
		t.Errorf("FormatFrom(8) = %q, want %q", got, want)
	}
}

func TestFormatTo(t *testing.T) {
	color.NoColor = false

	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{
			name: "patch bump greens only the patch",
			from: "1.2.3", to: "1.2.4",
			want: "1.2.\x1b[32m4\x1b[0m",
		},
		{
			name: "minor bump greens the minor, its dot, and the patch",
			from: "1.2.3", to: "1.3.0",
			want: "1.\x1b[32m3\x1b[0m\x1b[32m.\x1b[0m\x1b[32m0\x1b[0m",
		},
		{
			// The `same` flag is already false once the minor differs, so the
			// patch greens even though its value did not change.
			name: "minor changes and patch does not: patch still greens",
			from: "1.2.3", to: "1.3.3",
			want: "1.\x1b[32m3\x1b[0m\x1b[32m.\x1b[0m\x1b[32m3\x1b[0m",
		},
		{
			name: "no change greens nothing",
			from: "1.2.3", to: "1.2.3",
			want: "1.2.3",
		},
		{
			name: "prerelease change greens the prerelease, not the dash",
			from: "1.2.3-alpha", to: "1.2.3-beta",
			want: "1.2.3-\x1b[32mbeta\x1b[0m",
		},
		{
			name: "metadata greens the plus and the metadata",
			from: "1.2.3", to: "1.2.4+meta",
			want: "1.2.\x1b[32m4\x1b[0m\x1b[32m+\x1b[0m\x1b[32mmeta\x1b[0m",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mod(t, "a", tt.from, tt.to)
			if got := m.FormatTo(); got != tt.want {
				t.Errorf("FormatTo() = %q, want %q", got, tt.want)
			}
		})
	}
}
