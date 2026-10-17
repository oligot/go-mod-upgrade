package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	xmodule "golang.org/x/mod/module"
)

const cacheTTL = 24 * time.Hour

// cacheSchema is the layout version of a cache entry. Bump it whenever the
// fields of VersionItem change name or meaning: entries written by an older
// binary would otherwise unmarshal cleanly, with the changed field taking its
// zero value, and be read as live data until they expire.
const cacheSchema = 1

type cacheEntry struct {
	Schema   int           `json:"v"`
	CachedAt time.Time     `json:"cachedAt"`
	Items    []VersionItem `json:"items"`
}

func cacheDir() (string, error) {
	if dir := os.Getenv("GOMODUPGRADE_CACHE_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "go-mod-upgrade"), nil
}

func cacheFile(modulePath string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	// EscapePath encodes uppercase as "!x" so filenames stay distinct on
	// case-insensitive filesystems (same scheme as the module proxy).
	escaped, err := xmodule.EscapePath(modulePath)
	if err != nil {
		return "", err
	}
	filename := strings.ReplaceAll(escaped, "/", "~") + ".json"
	return filepath.Join(dir, filename), nil
}

func readCache(modulePath string) ([]VersionItem, bool) {
	path, err := cacheFile(modulePath)
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	if entry.Schema != cacheSchema {
		return nil, false
	}
	if time.Since(entry.CachedAt) > cacheTTL {
		return nil, false
	}
	return entry.Items, true
}

func writeCache(modulePath string, items []VersionItem) {
	path, err := cacheFile(modulePath)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	entry := cacheEntry{Schema: cacheSchema, CachedAt: time.Now(), Items: items}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}
