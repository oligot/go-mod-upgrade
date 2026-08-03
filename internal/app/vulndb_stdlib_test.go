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
