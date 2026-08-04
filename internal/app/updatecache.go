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
//
// The permitted environment belongs too, since it decides where the answer comes from:
// GOPROXY=off turns an available upgrade into "up to date", and GOFLAGS can carry -mod.
// Keying on it means a run with a different one asks again rather than being handed an
// answer gathered under rules it did not ask for.
func updateKey(reqs []requirement, window string) string {
	sum := sha256.New()
	// Quoted, since a value holding a newline could otherwise pass itself off as the end of
	// a field and let two different sets of inputs hash alike.
	fmt.Fprintf(sum, "v2\nwindow=%q\n", window)
	for _, kv := range keyedEnv() {
		fmt.Fprintf(sum, "env=%q\n", kv)
	}
	// Sorted, since the requirements arrive in whatever order they were discovered and a key
	// that varied with it would never hit.
	paths := make([]string, 0, len(reqs))
	for _, r := range reqs {
		paths = append(paths, r.Path+"@"+r.Version)
	}
	slices.Sort(paths)
	for _, p := range paths {
		fmt.Fprintf(sum, "req=%q\n", p)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// loadUpdates returns a stored answer about available upgrades, when it was written, and
// whether one was found.
//
// The time comes from the file's own modification time rather than from anything inside it.
// storeUpdates writes a temporary file and renames it, so the mtime is when the answer was
// gathered, and a reader learns the age of what they are being handed without the format
// having to carry a timestamp that could disagree with it.
func loadUpdates(dir, key string) (map[string]state, time.Time, bool) {
	at := filepath.Join(dir, updateCacheDir, key+".json")
	body, err := os.ReadFile(at)
	if err != nil {
		return nil, time.Time{}, false
	}
	var written time.Time
	if info, err := os.Stat(at); err == nil {
		written = info.ModTime()
	}
	var found map[string]state
	if err := json.Unmarshal(body, &found); err != nil {
		log.WithFields(log.Fields{"path": at, "error": err}).
			Debug("Ignoring an unreadable cached upgrade list")
		return nil, time.Time{}, false
	}
	if found == nil {
		return nil, time.Time{}, false
	}
	return found, written, true
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

// cacheAge is how old a reused answer is, and whether that is known at all.
//
// A hit whose age could not be read is a real state rather than a zero one: reporting
// "age=0s" would claim the answer was gathered this instant, which is the one reading
// that makes a stale listing look current.
type cacheAge struct {
	of    time.Duration
	known bool
}

// String renders the age for a log field, saying so when it is not known.
//
// Rounded to the second, since the age of a cached answer is not decided at finer precision and
// "46h45m59.033004s" is arithmetic rather than an answer.
func (a cacheAge) String() string {
	if !a.known {
		return "unknown"
	}
	return a.of.Round(time.Second).String()
}

// loadUpgrades returns a recent answer about available upgrades, how old it is, and when there
// is none, what forces the fetch.
//
// The reason is returned rather than logged so the caller can say which directory it belongs to,
// and say it in the order the directories were given: a workspace reads its members at once.
//
// A miss is one hash disagreeing, so it cannot say which of the things the key covers moved --
// the window, the requirements or the environment. Naming any one of them would be a guess.
func loadUpgrades(cache, window string, reqs []requirement) (map[string]state, bool, cacheAge, string) {
	if cache == "" || window == "" {
		return nil, false, cacheAge{}, "no cache to answer from"
	}
	found, written, ok := loadUpdates(cache, updateKey(reqs, window))
	if !ok {
		return nil, false, cacheAge{}, "no recent answer for these requirements"
	}
	age := cacheAge{}
	if !written.IsZero() {
		// Clamped at zero, since a clock that moved backwards or a file dated in the future
		// would otherwise report a negative age, which reads as a release yet to happen.
		age = cacheAge{of: max(time.Since(written), 0), known: true}
	}
	return found, true, age, ""
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
