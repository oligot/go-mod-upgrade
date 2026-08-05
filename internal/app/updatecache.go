package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// An entry saves the resolution of one "path@version" argument, around 60ms. That cost is the
// toolchain resolving a module version, not a proxy round trip, so an entry earns its keep on a
// warm module cache as much as on a cold one.

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

// moduleKey identifies what the toolchain reported about one module at one version.
//
// One module rather than the whole require block, so that editing one line of go.mod costs a
// query for that line. Keyed on the set, a single changed requirement missed the only entry there
// was and re-queried every module beside it.
//
// The version is part of the key because the answer is about it: what is newer than v1.0.0 is not
// what is newer than v1.1.0, and a retraction applies to the version in use. The directory is not,
// since "go list -m path@version" resolves without reference to any main module's build list, and
// nor is the go directive, which does not filter what a proxy offers. Leaving both out is what
// lets the members of a workspace share entries for the modules they share.
//
// The window decides when, since the same question asked a day later is a different one, and the
// permitted environment decides where the answer comes from: GOPROXY=off turns an available
// upgrade into "up to date", and GOFLAGS can carry -mod. Keying on the environment means a run
// with a different one asks again rather than being handed an answer gathered under rules it did
// not ask for.
func moduleKey(r requirement, window string) string {
	sum := sha256.New()
	// Quoted, since a value holding a newline could otherwise pass itself off as the end of
	// a field and let two different sets of inputs hash alike.
	fmt.Fprintf(sum, "v3\nwindow=%q\n", window)
	// The offline copy leaves GOPROXY out, since the run that reads it is by definition one
	// whose GOPROXY differs from the run that wrote it. Keyed on it, the entry could never
	// be found by the only caller it exists for.
	env := keyedEnv()
	if window == anyWindow {
		env = keyedEnvExcept("GOPROXY")
	}
	for _, kv := range env {
		fmt.Fprintf(sum, "env=%q\n", kv)
	}
	fmt.Fprintf(sum, "mod=%q\n", r.Path+"@"+r.Version)
	return hex.EncodeToString(sum.Sum(nil))
}

// loadAnswer returns what was stored about one module, when it was written, and whether an entry
// was found.
//
// The time comes from the file's own modification time rather than from anything inside it.
// storeAnswer writes a temporary file and renames it, so the mtime is when the answer was
// gathered, and a reader learns the age of what they are being handed without the format
// having to carry a timestamp that could disagree with it.
func loadAnswer(dir, key string) (state, time.Time, bool) {
	at := filepath.Join(dir, updateCacheDir, key+".json")
	body, err := os.ReadFile(at)
	if err != nil {
		return state{}, time.Time{}, false
	}
	var written time.Time
	if info, err := os.Stat(at); err == nil {
		written = info.ModTime()
	}
	var s state
	if err := json.Unmarshal(body, &s); err != nil {
		log.WithFields(log.Fields{"path": at, "error": err}).
			Debug("Ignoring an unreadable cached upgrade")
		return state{}, time.Time{}, false
	}
	return s, written, true
}

// storeAnswer records what the toolchain reported about one module.
//
// Written to a temporary file and renamed, so a run interrupted mid-write leaves no partial
// entry for the next one to read.
func storeAnswer(dir, key string, s state) error {
	at := filepath.Join(dir, updateCacheDir)
	if err := os.MkdirAll(at, 0o755); err != nil {
		return fmt.Errorf("error creating %q: %w", at, err)
	}
	body, err := json.Marshal(s)
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

// staleness gathers the age of a listing assembled from several cached entries.
//
// A listing is only as current as its oldest part, so the entries fold to the oldest rather than
// to the last one read. An entry whose date could not be read leaves the whole age unknown rather
// than being skipped, since it is not evidence of freshness, and "0s" is the one rendering that
// makes a stale listing look current.
type staleness struct {
	// oldest is when the earliest entry folded in was written.
	oldest time.Time
	// undated is set by an entry whose modification time could not be read.
	undated bool
	// some is whether anything was folded in at all, which separates a listing of unknown age
	// from one that reused nothing.
	some bool
}

// add folds in an entry written at the given moment.
func (s *staleness) add(written time.Time) {
	s.some = true
	if written.IsZero() {
		s.undated = true
		return
	}
	if s.oldest.IsZero() || written.Before(s.oldest) {
		s.oldest = written
	}
}

// merge folds in another listing's staleness, so an answer assembled from two sources is reported
// by the oldest entry in either.
func (s staleness) merge(o staleness) staleness {
	if !o.some {
		return s
	}
	if o.undated {
		s.add(time.Time{})
		return s
	}
	s.add(o.oldest)
	return s
}

// age is how old the listing is, which is not known until something datable is folded in.
func (s staleness) age() cacheAge {
	if !s.some || s.undated || s.oldest.IsZero() {
		return cacheAge{}
	}
	// Clamped at zero, since a clock that moved backwards or a file dated in the future
	// would otherwise report a negative age, which reads as a release yet to happen.
	return cacheAge{of: max(time.Since(s.oldest), 0), known: true}
}

// loadUpgrades returns what recent answers establish about these requirements, which of them no
// answer covers, how old the reused ones are, and when any have to be fetched, what forces it.
//
// Partial by design. One entry per module means an edited go.mod costs a query for the lines that
// moved rather than for every line beside them, so the ordinary result is most requirements
// answered and a few not.
//
// The reason is returned rather than logged so the caller can say which directory it belongs to,
// and say it in the order the directories were given: a workspace reads its members at once.
//
// A miss is one hash disagreeing, so it cannot say which of the things the key covers moved --
// the version, the window or the environment. Naming any one of them would be a guess.
func loadUpgrades(cache, window string, reqs []requirement) (map[string]state, []requirement, staleness, string) {
	found := make(map[string]state, len(reqs))
	if cache == "" || window == "" {
		return found, reqs, staleness{}, "no cache to answer from"
	}
	var missing []requirement
	var st staleness
	for _, r := range reqs {
		s, written, ok := loadAnswer(cache, moduleKey(r, window))
		if !ok {
			missing = append(missing, r)
			continue
		}
		found[r.Path] = s
		st.add(written)
	}
	switch {
	case len(missing) == 0:
		return found, nil, st, ""
	case len(missing) == len(reqs):
		return found, missing, st, "no recent answer for these requirements"
	default:
		// Counted, since what a partial miss costs is what is left to ask, and a reader
		// weighing an eight-second wait wants to know it is buying three modules.
		return found, missing, st, fmt.Sprintf("no recent answer for %d of %d requirements",
			len(missing), len(reqs))
	}
}

// saveUpgrades records what the toolchain reported about each requirement for the rest of the
// window.
//
// A failure to record is not a failure to ask: the answer is in hand, and the next run pays for
// the network again rather than being told the tree is broken.
//
// Each module is written twice: once under the window, which is what an ordinary run reads, and
// once without it, which is what an offline run falls back to. The second is a copy rather than a
// link so that a swept window entry cannot take the fallback with it.
//
// A module marked unknown is not recorded, and neither is one the toolchain reported an error
// about. Neither establishes anything, and an entry saying so would be reused for the rest of the
// window by runs that may well have a proxy again, turning one unreachable moment into a day of
// unchecked modules.
func saveUpgrades(cache, window string, reqs []requirement, found map[string]state) {
	if cache == "" || window == "" {
		return
	}
	for _, r := range reqs {
		s, ok := found[r.Path]
		if !ok || s.Unknown {
			continue
		}
		if err := storeAnswer(cache, moduleKey(r, window), s); err != nil {
			log.WithFields(log.Fields{"module": r.Path, "error": err}).
				Debug("Could not record an upgrade")
		}
		if err := storeAnswer(cache, moduleKey(r, anyWindow), s); err != nil {
			log.WithFields(log.Fields{"module": r.Path, "error": err}).
				Debug("Could not record an upgrade for offline use")
		}
	}
}

// anyWindow keys the copy an offline run reads, standing where a window would.
//
// A literal rather than an empty string, since an empty window already means "do not cache at
// all" and the two must not be confused. Not a real instant, so no ordinary run can collide
// with it.
const anyWindow = "offline"

// loadAnyUpgrades returns the last answer recorded about each of these requirements whatever
// window it was gathered in, which of them none covers, and how old the reused ones are.
//
// For offline runs, where the window is beside the point: it exists to stop a fresh answer being
// reused past its usefulness, and offline there is no fresh answer to prefer. The module, its
// version and the environment are still part of the key, so this cannot hand back an answer about
// a version no longer required.
func loadAnyUpgrades(cache string, reqs []requirement) (map[string]state, []requirement, staleness) {
	found, missing, st, _ := loadUpgrades(cache, anyWindow, reqs)
	return found, missing, st
}
