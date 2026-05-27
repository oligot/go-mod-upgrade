package api

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestCacheRoundTrip(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	items := []VersionItem{
		{ModulePath: "github.com/foo/bar/v2", Version: "v2.0.0"},
	}
	writeCache("github.com/foo/bar", items)

	got, ok := readCache("github.com/foo/bar")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 || got[0].Version != "v2.0.0" {
		t.Errorf("unexpected items: %+v", got)
	}
}

func TestCacheMiss_NonExistent(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	_, ok := readCache("github.com/foo/bar")
	if ok {
		t.Error("expected cache miss for non-existent entry")
	}
}

func TestCacheMiss_Expired(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	entry := cacheEntry{
		CachedAt: time.Now().Add(-25 * time.Hour),
		Items:    []VersionItem{{ModulePath: "github.com/foo/bar/v2", Version: "v2.0.0"}},
	}
	data, _ := json.Marshal(entry)
	path, _ := cacheFile("github.com/foo/bar")
	_ = os.WriteFile(path, data, 0644)

	_, ok := readCache("github.com/foo/bar")
	if ok {
		t.Error("expected cache miss for expired entry")
	}
}
