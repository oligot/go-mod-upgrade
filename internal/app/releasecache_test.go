package app

import (
	"path/filepath"
	"testing"
	"time"
)

// TestReleaseCacheRoundTrips checks that a module's release history survives being stored and
// read back.
//
// A published version's date never changes, so this needs no invalidation: the entry is keyed
// on the module path and holds what was learned about it. Checking release history is the most
// expensive phase of a run at 47%, entirely because it asks the toolchain the same immutable
// question every time.
func TestReleaseCacheRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := []release{
		{Version: "v1.27.6", Time: time.Date(2026, 7, 31, 18, 46, 10, 0, time.UTC)},
		{Version: "v1.27.4", Time: time.Date(2026, 7, 16, 18, 53, 26, 0, time.UTC)},
	}

	if err := storeReleases(dir, "github.com/aws/smithy-go", want); err != nil {
		t.Fatalf("storeReleases: %v", err)
	}
	got, ok := loadReleases(dir, "github.com/aws/smithy-go")
	if !ok {
		t.Fatal("loadReleases found nothing, want the stored history")
	}
	if len(got) != len(want) {
		t.Fatalf("loadReleases() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Version != want[i].Version || !got[i].Time.Equal(want[i].Time) {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Another module is another question.
	if _, ok := loadReleases(dir, "example.com/other"); ok {
		t.Error("loadReleases hit on a different module, want a miss")
	}
}

// TestReleaseCacheKeyIsAPath checks that a module path becomes a usable filename.
//
// A module path holds slashes, dots and upper case, and on a case-insensitive filesystem
// "github.com/Sirupsen/logrus" and "github.com/sirupsen/logrus" are different modules that
// would otherwise share an entry.
func TestReleaseCacheKeyIsAPath(t *testing.T) {
	seen := map[string]string{}
	for _, path := range []string{
		"github.com/aws/smithy-go",
		"github.com/Sirupsen/logrus",
		"github.com/sirupsen/logrus",
		"gopkg.in/yaml.v3",
		"golang.org/x/text",
	} {
		key := releaseKey(path)
		if key != filepath.Base(key) || key == "" {
			t.Errorf("releaseKey(%q) = %q, want a single path element", path, key)
		}
		if was, had := seen[key]; had {
			t.Errorf("releaseKey(%q) collides with %q", path, was)
		}
		seen[key] = path
	}
}

// TestReleaseCacheGrowsRatherThanReplaces checks that a stale entry is extended rather than
// trusted whole.
//
// A version list only grows, so a cached history is a floor rather than an answer: the module
// may have published since. Merging keeps the immutable dates without pretending the list is
// complete.
func TestReleaseCacheMergesNewReleases(t *testing.T) {
	cached := []release{
		{Version: "v1.27.4", Time: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)},
	}
	fresh := []release{
		{Version: "v1.27.6", Time: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)},
		{Version: "v1.27.4", Time: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)},
	}
	got := mergeReleases(cached, fresh)
	if len(got) != 2 {
		t.Fatalf("mergeReleases() = %v, want both releases", got)
	}
	// Newest first, as the history is everywhere else.
	if got[0].Version != "v1.27.6" {
		t.Errorf("mergeReleases() = %v, want newest first", got)
	}
	// A date already known is not asked for again, so the cached one stands.
	if !got[1].Time.Equal(cached[0].Time) {
		t.Errorf("the cached date was lost: %v", got[1])
	}
}
