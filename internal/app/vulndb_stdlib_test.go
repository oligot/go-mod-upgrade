package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
)

// TestAffectedReadsDisjointWindows checks that an advisory's affected ranges are read as the
// intervals they are, including several per advisory.
//
// A CVE is not a range with one edge. GO-2021-0067 affects only [1.16.0, 1.16.1) -- a single
// point release -- and GO-2021-0069 has two disjoint windows, [1.14.0, 1.14.12) and
// [1.15.0, 1.15.5). Reading only the first, or treating the newest fix as a floor, would
// call a clean version affected and an affected one clean.
func TestAffectedReadsDisjointWindows(t *testing.T) {
	// The shape the Go vulnerability database publishes, trimmed to what is read. The
	// "1.15.0-0" sentinel is how it says "the start of the 1.15 line, including its RCs".
	body := `{
      "id": "GO-2021-0069",
      "affected": [{
        "package": {"name": "stdlib", "ecosystem": "Go"},
        "ranges": [{
          "type": "SEMVER",
          "events": [
            {"introduced": "1.14.0-0"}, {"fixed": "1.14.12"},
            {"introduced": "1.15.0-0"}, {"fixed": "1.15.5"}
          ]
        }]
      }]
    }`

	var rec osvAdvisory
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := rec.windows()
	if len(got) != 2 {
		t.Fatalf("windows() = %v, want two disjoint windows", got)
	}

	for _, tc := range []struct {
		version  string
		affected bool
	}{
		// Inside the first window.
		{version: "1.14.0", affected: true},
		{version: "1.14.11", affected: true},
		// The fix itself is outside: the interval is right-open.
		{version: "1.14.12", affected: false},
		// Between the windows, which is why a single range would be wrong.
		{version: "1.14.13", affected: false},
		// Inside the second.
		{version: "1.15.0", affected: true},
		{version: "1.15.4", affected: true},
		{version: "1.15.5", affected: false},
		// Outside both.
		{version: "1.13.0", affected: false},
		{version: "1.26.5", affected: false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			v := semver.MustParse(tc.version)
			if affected(v, got) != tc.affected {
				t.Errorf("affected(%s) = %v, want %v", tc.version, !tc.affected, tc.affected)
			}
		})
	}
}

// TestAffectedHandlesOpenAndAbsentRanges checks the two edge shapes the database uses.
//
// "introduced": "0" means every version up to the fix, and an advisory with no ranges at all
// means every version -- so both have to read as affected rather than as nothing known.
func TestAffectedHandlesOpenAndAbsentRanges(t *testing.T) {
	open := `{"id":"GO-X","affected":[{"package":{"name":"stdlib"},
      "ranges":[{"events":[{"introduced":"0"},{"fixed":"1.16.1"}]}]}]}`
	var rec osvAdvisory
	if err := json.Unmarshal([]byte(open), &rec); err != nil {
		t.Fatal(err)
	}
	w := rec.windows()
	if !affected(semver.MustParse("1.2.0"), w) {
		t.Error("a version below the fix is not affected, want it affected from zero")
	}
	if affected(semver.MustParse("1.16.1"), w) {
		t.Error("the fix itself reads as affected, want the interval right-open")
	}

	// No fix at all: affected from the introduction onwards, with no upper edge.
	unfixed := `{"id":"GO-Y","affected":[{"package":{"name":"stdlib"},
      "ranges":[{"events":[{"introduced":"1.20.0"}]}]}]}`
	if err := json.Unmarshal([]byte(unfixed), &rec); err != nil {
		t.Fatal(err)
	}
	w = rec.windows()
	if !affected(semver.MustParse("1.26.5"), w) {
		t.Error("an unfixed advisory does not affect a later version, want no upper edge")
	}
	if affected(semver.MustParse("1.19.0"), w) {
		t.Error("a version below the introduction is affected, want it clean")
	}
}

// TestAffectedIgnoresOtherPackages checks that only the standard library's own ranges are
// read, since one advisory record can carry several packages.
func TestAffectedIgnoresOtherPackages(t *testing.T) {
	body := `{"id":"GO-Z","affected":[
      {"package":{"name":"golang.org/x/net"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]},
      {"package":{"name":"stdlib"},"ranges":[{"events":[{"introduced":"1.20.0"},{"fixed":"1.20.1"}]}]}
    ]}`
	var rec osvAdvisory
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatal(err)
	}
	w := rec.windows()
	if len(w) != 1 {
		t.Fatalf("windows() = %v, want only the stdlib range", w)
	}
	// The x/net range would have swallowed everything below 9.9.9.
	if affected(semver.MustParse("1.26.5"), w) {
		t.Error("1.26.5 reads as affected, want another package's range ignored")
	}
}

// TestStdlibWindowsReadsTheCache checks that the advisories are found through the database's
// own index rather than by walking every record.
//
// The index names 160 stdlib advisories out of 4134 in the database, so reading it is both
// faster and the documented way in.
func TestStdlibWindowsReadsTheCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "index"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "ID"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("index/modules.json", `[
      {"path":"golang.org/x/net","vulns":[{"id":"GO-OTHER"}]},
      {"path":"stdlib","vulns":[{"id":"GO-A"},{"id":"GO-B"},{"id":"GO-MISSING"}]}
    ]`)
	write("ID/GO-A.json", `{"id":"GO-A","affected":[{"package":{"name":"stdlib"},
      "ranges":[{"events":[{"introduced":"1.25.0-0"},{"fixed":"1.25.12"}]}]}]}`)
	write("ID/GO-B.json", `{"id":"GO-B","affected":[{"package":{"name":"stdlib"},
      "ranges":[{"events":[{"introduced":"1.26.0-0"},{"fixed":"1.26.3"}]}]}]}`)
	// GO-MISSING has no record; a truncated cache must not fail the read.

	got, err := stdlibWindows(dir)
	if err != nil {
		t.Fatalf("stdlibWindows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("stdlibWindows() = %v, want two windows", got)
	}
	for _, tc := range []struct {
		version  string
		affected bool
	}{
		{version: "1.25.11", affected: true},
		{version: "1.25.12", affected: false},
		{version: "1.26.2", affected: true},
		{version: "1.26.5", affected: false},
	} {
		if affected(semver.MustParse(tc.version), got) != tc.affected {
			t.Errorf("affected(%s) = %v, want %v", tc.version, !tc.affected, tc.affected)
		}
	}
}

// TestStdlibWindowsByIDKeysAndSkips covers the map a caller reads to decide which advisory
// covers a version.
//
// The absent keys carry the meaning: a key holding no window would read as an advisory known
// to cover no version, which would clear a real finding.
func TestStdlibWindowsByIDKeysAndSkips(t *testing.T) {
	dir := t.TempDir()
	for _, at := range []string{"index", "ID"} {
		if err := os.MkdirAll(filepath.Join(dir, at), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("index/modules.json", `[
      {"path":"stdlib","vulns":[{"id":"GO-A"},{"id":"GO-ELSEWHERE"},{"id":"GO-MISSING"}]}
    ]`)
	write("ID/GO-A.json", `{"id":"GO-A","affected":[{"package":{"name":"stdlib"},
      "ranges":[{"events":[{"introduced":"0"},{"fixed":"1.25.12"}]},
                {"events":[{"introduced":"1.26.0-0"},{"fixed":"1.26.5"}]}]}]}`)
	write("ID/GO-ELSEWHERE.json", `{"id":"GO-ELSEWHERE","affected":[{"package":{"name":"golang.org/x/net"},
      "ranges":[{"events":[{"introduced":"0"},{"fixed":"0.38.0"}]}]}]}`)

	got, err := stdlibWindowsByID(dir)
	if err != nil {
		t.Fatalf("stdlibWindowsByID: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("stdlibWindowsByID() = %v, want GO-A alone", got)
	}
	if _, ok := got["GO-ELSEWHERE"]; ok {
		t.Error("an advisory naming another package is keyed, want it left out")
	}
	if _, ok := got["GO-MISSING"]; ok {
		t.Error("an advisory absent from the cache is keyed, want it left out")
	}
	// Both lines reach the one key, so a 1.25 declaration meets the 1.25 fix.
	if len(got["GO-A"]) != 2 {
		t.Fatalf("GO-A = %v, want both windows", got["GO-A"])
	}
}

// TestClearedNeedsTheFixOnItsOwnLine pins when an advisory stops applying.
//
// Outside every window is not enough: that also describes a version older than the defect, and
// a go directive is a floor an affected toolchain can honour.
func TestClearedNeedsTheFixOnItsOwnLine(t *testing.T) {
	twoLines := []window{
		{From: &semver.Version{}, To: semver.MustParse("1.25.12")},
		{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.5")},
	}
	laterLine := []window{{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.4")}}
	unfixed := []window{{From: &semver.Version{}}}

	cases := []struct {
		name    string
		version string
		windows []window
		want    bool
	}{
		{name: "inside the first window", version: "1.25.9", windows: twoLines, want: false},
		{name: "at the fix on its own line", version: "1.25.12", windows: twoLines, want: true},
		{name: "inside the second window", version: "1.26.4", windows: twoLines, want: false},
		{name: "at the fix on the second line", version: "1.26.5", windows: twoLines, want: true},
		{
			// Fixed on its own line, whatever a later one still covers.
			name:    "fixed on its own line while a later one is covered",
			version: "1.25.12",
			windows: append([]window{{From: semver.MustParse("1.27.0-0"), To: semver.MustParse("1.27.0-rc.2")}}, twoLines...),
			want:    true,
		},
		{
			// Older than the defect, which says nothing about what builds it.
			name:    "below every window",
			version: "1.24.0",
			windows: laterLine,
			want:    false,
		},
		{name: "nothing fixes it yet", version: "1.26.5", windows: unfixed, want: false},
		{name: "no ranges at all", version: "1.26.5", windows: nil, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cleared(semver.MustParse(c.version), c.windows); got != c.want {
				t.Errorf("cleared(%s) = %t, want %t", c.version, got, c.want)
			}
		})
	}
}

// TestFixForNamesTheSmallestMove pins the version a row recommends: the fix on the
// declaration's own line where there is one, since raising a go directive is a demand on every
// consumer, and otherwise the lowest above it.
func TestFixForNamesTheSmallestMove(t *testing.T) {
	twoLines := []window{
		{From: &semver.Version{}, To: semver.MustParse("1.25.12")},
		{From: semver.MustParse("1.26.0-0"), To: semver.MustParse("1.26.5")},
	}
	cases := []struct {
		name    string
		version string
		windows []window
		want    string
	}{
		{name: "the fix on its own line", version: "1.25.9", windows: twoLines, want: "1.25.12"},
		{name: "the fix on the line it sits in", version: "1.26.4", windows: twoLines, want: "1.26.5"},
		{
			// Only the lower of the two above it has to be cleared.
			name:    "the lowest fix above it",
			version: "1.24.0",
			windows: twoLines,
			want:    "1.25.12",
		},
		{
			// A prerelease fix is what was published, so it is what gets named.
			name:    "a prerelease fix above it",
			version: "1.23.0",
			windows: []window{{From: semver.MustParse("1.24.0-0"), To: semver.MustParse("1.24.0-rc.2")}},
			want:    "1.24.0-rc.2",
		},
		{
			name:    "nothing fixes it yet",
			version: "1.26.4",
			windows: []window{{From: &semver.Version{}}},
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fixFor(semver.MustParse(c.version), c.windows)
			if c.want == "" {
				if got != nil {
					t.Errorf("fixFor(%s) = %v, want nil", c.version, got)
				}
				return
			}
			if got == nil || got.String() != c.want {
				t.Errorf("fixFor(%s) = %v, want %s", c.version, got, c.want)
			}
		})
	}
}
