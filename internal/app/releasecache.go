package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// releaseCacheDir is where release histories live inside the cache directory, beside the
// vulnerability database and the scan results.
const releaseCacheDir = "releases"

// releaseKey turns a module path into a filename.
//
// A path holds slashes, dots and upper case, so it cannot be a filename as it stands -- and on
// a case-insensitive filesystem "github.com/Sirupsen/logrus" and "github.com/sirupsen/logrus"
// are different modules that would otherwise share an entry. A hash sidesteps both, and the
// path is recorded inside the entry so a reader can still tell what it holds.
func releaseKey(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// releaseRecord is a module's release history as it is stored.
//
// The path is kept so an entry says what it is about, which matters when the filename is a
// hash: a cache nobody can read is a cache nobody can debug.
type releaseRecord struct {
	Module   string    `json:"module"`
	Releases []release `json:"releases"`
}

// loadReleases returns a module's stored release history, and whether one was found.
//
// The dates in it need no invalidation. A published version's date never changes, so what was
// learned about v1.27.4 last week is still true -- which is what makes this phase, the most
// expensive in a run, almost entirely avoidable.
//
// The list of versions is another matter: a module may have published since. The caller treats
// what comes back as a floor rather than an answer.
func loadReleases(dir, path string) ([]release, bool) {
	at := filepath.Join(dir, releaseCacheDir, releaseKey(path)+".json")
	body, err := os.ReadFile(at)
	if err != nil {
		return nil, false
	}
	var record releaseRecord
	if err := json.Unmarshal(body, &record); err != nil {
		log.Trace().Fields(map[string]any{"path": at, "error": err}).Msg("Ignoring an unreadable cached release history")
		return nil, false
	}
	// A hash collision would be a different module's history, which is worse than a miss.
	if record.Module != path {
		return nil, false
	}
	return record.Releases, len(record.Releases) > 0
}

// storeReleases records a module's release history.
//
// Written to a temporary file and renamed, so a run interrupted mid-write leaves no partial
// entry for the next one to read.
func storeReleases(dir, path string, found []release) error {
	at := filepath.Join(dir, releaseCacheDir)
	if err := os.MkdirAll(at, 0o755); err != nil {
		return fmt.Errorf("error creating %q: %w", at, err)
	}
	body, err := json.Marshal(releaseRecord{Module: path, Releases: found})
	if err != nil {
		return fmt.Errorf("error recording a release history: %w", err)
	}
	key := releaseKey(path)
	tmp, err := os.CreateTemp(at, key+".*")
	if err != nil {
		return fmt.Errorf("error recording a release history: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(body)
	if closeErr := tmp.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		if rmErr := os.Remove(name); rmErr != nil {
			log.Trace().Err(rmErr).Msg("Could not remove a partial release history")
		}
		return fmt.Errorf("error recording a release history: %w", err)
	}
	return os.Rename(name, filepath.Join(at, key+".json"))
}

// mergeReleases combines a cached history with a freshly read one, newest first.
//
// The fresh list decides which versions exist, since it is the current answer. The cached list
// supplies the dates it already holds, which is the expensive part and which cannot have
// changed. So a module that published once since the last run costs one date rather than
// twenty.
func mergeReleases(cached, fresh []release) []release {
	dates := make(map[string]release, len(cached))
	for _, r := range cached {
		dates[r.Version] = r
	}
	out := make([]release, 0, len(fresh))
	for _, r := range fresh {
		if r.Time.IsZero() {
			if was, had := dates[r.Version]; had {
				out = append(out, was)
				continue
			}
		}
		out = append(out, r)
	}
	// Newest first, as every other history in this package is.
	slices.SortStableFunc(out, func(a, b release) int {
		return strings.Compare(b.Version, a.Version)
	})
	return out
}
