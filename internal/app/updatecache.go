package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/apex/log"
)

// DefaultUpdateWindow is how long an answer about available upgrades is reused when --cache-for
// is not given.
//
// A day, because that is the granularity at which the answer usefully changes: a dependency
// that published this morning is worth hearing about tomorrow, and hearing about it eleven
// times today costs a network round trip each time to say the same thing.
const DefaultUpdateWindow = "1d"

// updateCacheDir is where answers about available upgrades live inside the cache directory.
const updateCacheDir = "updates"

// How much this saves depends entirely on Go's own module cache. Cold, "-u" costs 1.24s against
// 0.06s without it; warm, both are around 0.07s, because Go caches proxy responses itself. So
// this earns its keep on a first run, in CI with no warm cache, and offline -- not on the tenth
// run of the afternoon, where the saving is within noise.

// updateWindow returns the key fragment naming the window a moment falls in.
//
// "go list -m -u" asks what upgrade exists right now, and the answer changes when upstream
// publishes -- which alters nothing on disk. A key made only of the requirements would
// therefore keep reporting last week's answer for as long as go.mod stood still, and the one
// question this tool exists to answer would stop being asked.
//
// So time is part of the key, masked by the window: every run inside one shares a key, and the
// first run after it asks again. Masked rather than compared against a stored timestamp, since
// a boundary is a thing two runs can agree on where "within a day of when I looked" is not.
//
// A zero window means never reuse, so every moment is its own key.
func updateWindow(at time.Time, window time.Duration) string {
	if window <= 0 {
		return strconv.FormatInt(at.UnixNano(), 10)
	}
	return strconv.FormatInt(at.Unix()/int64(window.Seconds()), 10)
}

// updateKey identifies an answer about available upgrades.
//
// The requirements decide which modules were asked about, and the window decides when. Both
// belong: a changed go.mod is a different question, and so is the same question asked a day
// later.
func updateKey(reqs []requirement, window string) string {
	sum := sha256.New()
	fmt.Fprintf(sum, "v1\nwindow=%s\n", window)
	// Sorted, since the requirements arrive in whatever order they were discovered and a key
	// that varied with it would never hit.
	paths := make([]string, 0, len(reqs))
	for _, r := range reqs {
		paths = append(paths, r.Path+"@"+r.Version)
	}
	slices.Sort(paths)
	for _, p := range paths {
		fmt.Fprintf(sum, "%s\n", p)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// loadUpdates returns a stored answer about available upgrades, and whether one was found.
func loadUpdates(dir, key string) (map[string]state, bool) {
	at := filepath.Join(dir, updateCacheDir, key+".json")
	body, err := os.ReadFile(at)
	if err != nil {
		return nil, false
	}
	var found map[string]state
	if err := json.Unmarshal(body, &found); err != nil {
		log.WithFields(log.Fields{"path": at, "error": err}).
			Debug("Ignoring an unreadable cached upgrade list")
		return nil, false
	}
	if found == nil {
		return nil, false
	}
	return found, true
}

// storeUpdates records what the toolchain said about available upgrades.
//
// Written to a temporary file and renamed, so a run interrupted mid-write leaves no partial
// entry for the next one to read.
func storeUpdates(dir, key string, found map[string]state) error {
	at := filepath.Join(dir, updateCacheDir)
	if err := os.MkdirAll(at, 0o755); err != nil {
		return fmt.Errorf("error creating %q: %w", at, err)
	}
	if found == nil {
		found = map[string]state{}
	}
	body, err := json.Marshal(found)
	if err != nil {
		return fmt.Errorf("error recording the upgrade list: %w", err)
	}
	tmp, err := os.CreateTemp(at, key+".*")
	if err != nil {
		return fmt.Errorf("error recording the upgrade list: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(body)
	if closeErr := tmp.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		if rmErr := os.Remove(name); rmErr != nil {
			log.WithError(rmErr).Debug("Could not remove a partial upgrade list")
		}
		return fmt.Errorf("error recording the upgrade list: %w", err)
	}
	return os.Rename(name, filepath.Join(at, key+".json"))
}

// reused records that a remembered answer was used, so the run can say so at the end.
//
// Said once rather than per directory: a workspace of five members would otherwise report it
// five times, which reads as five different things having happened.
var reused struct {
	sync.Mutex
	on bool
}

// ReportCacheUse says whether the run answered from a remembered upgrade list.
//
// Worth saying because it changes what the output means: a listing built from yesterday's answer
// will not mention something published this morning. A reader who needs the current answer has
// to know they did not get one, and how to ask for it.
func ReportCacheUse() {
	reused.Lock()
	defer reused.Unlock()
	if !reused.on {
		return
	}
	log.WithField("disable", "--cache=false").
		Info("Available upgrades came from a recent answer rather than the proxy")
}

// loadUpgrades returns a recent answer about available upgrades, and whether one was found.
func loadUpgrades(cache, window string, reqs []requirement) (map[string]state, bool) {
	if cache == "" || window == "" {
		return nil, false
	}
	found, ok := loadUpdates(cache, updateKey(reqs, window))
	if ok {
		reused.Lock()
		reused.on = true
		reused.Unlock()
	}
	return found, ok
}

// saveUpgrades records an answer for the rest of the window.
//
// A failure to record is not a failure to ask: the answer is in hand, and the next run pays for
// the network again rather than being told the tree is broken.
func saveUpgrades(cache, window string, reqs []requirement, found map[string]state) {
	if cache == "" || window == "" {
		return
	}
	if err := storeUpdates(cache, updateKey(reqs, window), found); err != nil {
		log.WithError(err).Debug("Could not record the upgrade list")
	}
}

// mergeUpgrades combines what the module cache says about the installed versions with a
// remembered answer about what is published.
//
// The local read decides what is installed, deprecated and retracted, since those describe the
// tree as it stands. The remembered answer supplies only the upgrade and its date, which are
// the part that needed the network -- so a module whose requirement changed since is described
// correctly while still costing nothing to check for upgrades.
func mergeUpgrades(local, remembered map[string]state) map[string]state {
	out := make(map[string]state, len(local))
	for path, at := range local {
		if was, had := remembered[path]; had {
			at.Update, at.Released = was.Update, was.Released
		}
		out[path] = at
	}
	return out
}
