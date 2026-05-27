package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheTTL = 24 * time.Hour

type cacheEntry struct {
	CachedAt time.Time   `json:"cachedAt"`
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
	filename := strings.ReplaceAll(modulePath, "/", "~") + ".json"
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
	entry := cacheEntry{CachedAt: time.Now(), Items: items}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}
