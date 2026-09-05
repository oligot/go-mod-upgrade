package discover

import (
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
)

// Captured `go list -m -versions github.com/prometheus/client_golang` output,
// truncated. Note the prerelease tags: go does list them.
const versionsOutput = "github.com/prometheus/client_golang v1.23.0-rc.1 v1.23.0 v1.23.1 v1.23.2 v1.24.0-rc.0 v1.24.0 v1.24.1\n"

func TestParseVersions(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		after   string
		want    []string
		wantErr bool
	}{
		{
			name:  "keeps only versions above after",
			out:   versionsOutput,
			after: "v1.23.2",
			want:  []string{"v1.24.0-rc.0", "v1.24.0", "v1.24.1"},
		},
		{
			name:  "after excludes itself",
			out:   versionsOutput,
			after: "v1.24.1",
			want:  nil,
		},
		{
			name:  "no versions newer is not an error",
			out:   "example.com/mod v1.0.0\n",
			after: "v1.0.0",
			want:  nil,
		},
		{
			name:  "a module with no tagged versions at all is not an error",
			out:   "example.com/mod\n",
			after: "v1.0.0",
			want:  nil,
		},
		{
			name:  "unparseable versions are skipped, not fatal",
			out:   "example.com/mod v1.1.0 nonsense v1.2.0\n",
			after: "v1.0.0",
			want:  []string{"v1.1.0", "v1.2.0"},
		},
		{
			name:  "output is sorted ascending rather than trusted",
			out:   "example.com/mod v1.10.0 v1.2.0 v1.9.0\n",
			after: "v1.0.0",
			want:  []string{"v1.2.0", "v1.9.0", "v1.10.0"},
		},
		{
			name:  "incompatible major versions are kept verbatim",
			out:   "example.com/mod v1.0.0 v2.0.0+incompatible\n",
			after: "v1.0.0",
			want:  []string{"v2.0.0+incompatible"},
		},
		{
			name:    "empty output is an error",
			out:     "",
			wantErr: true,
			after:   "v1.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVersions([]byte(tt.out), semver.MustParse(tt.after))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseVersions() = %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVersions() returned unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseVersions() = %v, want %v", got, tt.want)
			}
			for i, want := range tt.want {
				// Original is what the publish-time queries and the display use.
				if got[i].Original() != want {
					t.Errorf("parseVersions()[%d] = %q, want %q", i, got[i].Original(), want)
				}
			}
		})
	}
}

// Captured `go list -m -json github.com/fatih/color@v1.16.0
// github.com/fatih/color@v1.17.0` output, with the fields we ignore trimmed.
const timesOutput = `{
	"Path": "github.com/fatih/color",
	"Version": "v1.16.0",
	"Time": "2023-11-06T08:25:55Z",
	"GoVersion": "1.17"
}
{
	"Path": "github.com/fatih/color",
	"Version": "v1.17.0",
	"Time": "2024-04-08T12:08:58Z",
	"GoVersion": "1.17"
}
`

func TestParseTimes(t *testing.T) {
	times, err := parseTimes([]byte(timesOutput))
	if err != nil {
		t.Fatalf("parseTimes() returned unexpected error: %v", err)
	}
	if len(times) != 2 {
		t.Fatalf("parseTimes() = %v, want 2 entries", times)
	}
	// The keys must be reachable from a parsed version, which is how
	// versionLookup joins the two go invocations back together.
	for _, tt := range []struct {
		version string
		want    string
	}{
		{"v1.16.0", "2023-11-06T08:25:55Z"},
		{"v1.17.0", "2024-04-08T12:08:58Z"},
	} {
		want, err := time.Parse(time.RFC3339, tt.want)
		if err != nil {
			t.Fatalf("bad test data %q: %v", tt.want, err)
		}
		got, ok := times[semver.MustParse(tt.version).Original()]
		if !ok {
			t.Fatalf("parseTimes() has no entry for %s, keys are %v", tt.version, times)
		}
		if !got.Equal(want) {
			t.Errorf("parseTimes()[%s] = %s, want %s", tt.version, got, want)
		}
	}
}

func TestParseTimesMissingTimeDecodesToZero(t *testing.T) {
	// go omits Time when it can't determine it. The zero value must survive to
	// the caller, which treats it as an unverifiable age.
	times, err := parseTimes([]byte(`{"Path":"example.com/mod","Version":"v1.0.0"}`))
	if err != nil {
		t.Fatalf("parseTimes() returned unexpected error: %v", err)
	}
	if got, ok := times["v1.0.0"]; !ok || !got.IsZero() {
		t.Errorf("parseTimes()[v1.0.0] = %s, ok = %t, want the zero time", got, ok)
	}
}

func TestParseTimesRejectsMalformedJSON(t *testing.T) {
	if _, err := parseTimes([]byte(`{"Path":`)); err == nil {
		t.Error("parseTimes() = nil error, want an error for truncated JSON")
	}
}
