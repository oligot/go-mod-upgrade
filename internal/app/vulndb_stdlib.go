package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"
)

// window is a range of versions one advisory covers, left-closed and right-open.
//
// Right-open because the fix version is the first one *not* affected: an advisory fixed in
// 1.14.12 covers 1.14.11 and not 1.14.12. To is nil when nothing fixes it yet, which leaves
// the window open at the top.
type window struct {
	From *semver.Version
	To   *semver.Version
}

func (w window) String() string {
	if w.To == nil {
		return fmt.Sprintf("[%s, )", w.From)
	}
	return fmt.Sprintf("[%s, %s)", w.From, w.To)
}

// osvAdvisory is the part of a published advisory that says which versions it covers.
//
// The database holds far more than this. What matters here is the affected ranges, which
// govulncheck's own output discards -- it reports a single fixed version per finding, which
// cannot express an advisory that covers two release lines.
type osvAdvisory struct {
	ID       string `json:"id"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// windows returns the version ranges this advisory covers in the standard library.
//
// One advisory can carry several, and they can be disjoint: GO-2021-0069 covers
// [1.14.0, 1.14.12) and [1.15.0, 1.15.5) but nothing between them, because each release line
// was fixed separately. Reading only the first range, or taking the newest fix as a floor,
// would call 1.14.13 affected when it is not.
//
// Only the standard library's own ranges are read, since one record can name several
// packages and another package's range says nothing about a toolchain version.
func (a osvAdvisory) windows() []window {
	var found []window
	for _, aff := range a.Affected {
		if aff.Package.Name != stdlibModule {
			continue
		}
		for _, r := range aff.Ranges {
			// Events arrive in order, an "introduced" opening a window and a "fixed"
			// closing it. A window left open by the end of the list is one nothing
			// fixes yet.
			var open *window
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					if open != nil {
						found = append(found, *open)
					}
					// "0" means every version from the beginning, which no real
					// version string says.
					from := &semver.Version{}
					if e.Introduced != "0" {
						v, err := semver.NewVersion(e.Introduced)
						if err != nil {
							open = nil
							continue
						}
						from = v
					}
					open = &window{From: from}
				case e.Fixed != "" && open != nil:
					v, err := semver.NewVersion(e.Fixed)
					if err != nil {
						open = nil
						continue
					}
					open.To = v
					found = append(found, *open)
					open = nil
				}
			}
			if open != nil {
				found = append(found, *open)
			}
		}
		// An advisory naming the package with no ranges at all covers every version of
		// it, which is what the OSV format says an empty range list means.
		if len(aff.Ranges) == 0 {
			found = append(found, window{From: &semver.Version{}})
		}
	}
	return found
}

// asRelease drops the prerelease, so a release candidate is judged as the release it leads to:
// 1.26.0-rc1 carries whatever 1.26.0 carries, since the vulnerable code is the same. The
// database's own "1.26.0-0" sentinel means the same thing from the other side.
//
// Every comparison against a window goes through this, so the rule is stated once.
func asRelease(v *semver.Version) semver.Version {
	return *semver.New(v.Major(), v.Minor(), v.Patch(), "", "")
}

// affected reports whether a version falls inside any window.
func affected(v *semver.Version, windows []window) bool {
	at := asRelease(v)
	for _, w := range windows {
		if at.LessThan(w.From) {
			continue
		}
		if w.To == nil {
			return true
		}
		if at.LessThan(w.To) {
			return true
		}
	}
	return false
}

// cleared reports whether a version has the fix for the release line it is on.
//
// Outside every window has two meanings, and only one of them is safe to act on. A version at
// or above a fix has that fix. A version below every window merely predates the defect, which
// says nothing about the toolchain that will build it: a go directive is a floor, so a project
// declaring 1.23.0 can be built by an affected 1.24.2, and raising the directive is what rules
// that out. So both halves are required, and the answer is about one release line rather than
// all of them: 1.14.12 has the fix an advisory published for the 1.14 line, whatever that
// advisory still covers on 1.15. What a later line carries is the running toolchain's business,
// which toolchainModule reports separately.
func cleared(v *semver.Version, windows []window) bool {
	at := asRelease(v)
	for _, w := range windows {
		if w.To != nil && !at.LessThan(w.To) {
			return !affected(v, windows)
		}
	}
	return false
}

// fixFor returns the version to raise a declaration to so an advisory stops covering it.
//
// The fix on the declaration's own release line where there is one, since that is the smallest
// change that works: an advisory backported to 1.25.12 and 1.26.5 is cleared for a 1.25
// project by 1.25.12, where the scan would name 1.26.5 and demand a minor bump.
//
// Otherwise the lowest fix above the declaration, which is the case for a declaration that
// predates every window: 1.23.0 against an advisory covering the 1.24 line only is cleared by
// moving past that line, and nothing lower would do it.
//
// Nil when the ranges name no fix at all, which leaves the scan's own answer to stand.
func fixFor(v *semver.Version, windows []window) *semver.Version {
	at := asRelease(v)
	var above *semver.Version
	for _, w := range windows {
		if w.To == nil {
			continue
		}
		if at.LessThan(w.From) {
			if above == nil || w.To.LessThan(above) {
				above = w.To
			}
			continue
		}
		if at.LessThan(w.To) {
			return w.To
		}
	}
	return above
}

// advisoryWindows holds the version ranges each advisory covers, keyed by advisory
// identifier. An identifier the map does not hold is one nothing is known about, which is what
// a truncated cache leaves behind.
type advisoryWindows map[string][]window

// stdlibWindows reads every version range the standard library's advisories cover, from the
// cached vulnerability database.
//
// The ranges of every advisory in one list, for a caller asking only whether some version is
// covered at all. A caller needing to know which advisory covers it reads stdlibWindowsByID.
// The order is arbitrary, since the ranges are gathered from a map.
func stdlibWindows(dir string) ([]window, error) {
	byID, err := stdlibWindowsByID(dir)
	if err != nil {
		return nil, err
	}
	var found []window
	for _, windows := range byID {
		found = append(found, windows...)
	}
	return found, nil
}

// stdlibWindowsByID reads the version ranges each standard library advisory covers, keyed by
// advisory identifier.
//
// Read through the database's own index rather than by walking every record: the index names
// 160 standard library advisories out of the 4134 published, so this opens 160 files instead
// of 4134.
//
// A record the index names but the cache does not hold is skipped rather than failing the
// read. A truncated copy should narrow the answer, not refuse to give one -- and the caller
// treats a missing advisory as "nothing known", which is the same posture. An advisory with no
// range of its own is left out for that reason: a key holding nothing would read as an
// advisory known to cover no version.
func stdlibWindowsByID(dir string) (advisoryWindows, error) {
	body, err := os.ReadFile(filepath.Join(dir, "index", "modules.json"))
	if err != nil {
		return nil, fmt.Errorf("reading the advisory index: %w", err)
	}
	var index []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("reading the advisory index: %w", err)
	}

	found := make(advisoryWindows)
	for _, m := range index {
		if m.Path != stdlibModule {
			continue
		}
		for _, v := range m.Vulns {
			// The identifier comes from the database's own index, but it names a file,
			// so it is cleaned rather than trusted.
			at := filepath.Join(dir, "ID", path.Base(v.ID)+".json")
			record, err := os.ReadFile(at)
			if err != nil {
				log.Trace().Fields(map[string]any{"advisory": v.ID, "error": err}).Msg("Advisory named by the index is not in the cache")
				continue
			}
			var a osvAdvisory
			if err := json.Unmarshal(record, &a); err != nil {
				log.Trace().Fields(map[string]any{"advisory": v.ID, "error": err}).Msg("Could not read an advisory")
				continue
			}
			if windows := a.windows(); len(windows) > 0 {
				found[v.ID] = append(found[v.ID], windows...)
			}
		}
	}
	return found, nil
}
