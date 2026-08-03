package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
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

// affected reports whether a version falls inside any window.
//
// The comparison drops the prerelease, so a release candidate is judged as the release it
// leads to: 1.26.0-rc1 carries whatever 1.26.0 carries, since the vulnerable code is the
// same. The database's own "1.26.0-0" sentinel means the same thing from the other side.
func affected(v *semver.Version, windows []window) bool {
	at := *semver.New(v.Major(), v.Minor(), v.Patch(), "", "")
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

// stdlibWindows reads every version range the standard library's advisories cover, from the
// cached vulnerability database.
//
// Read through the database's own index rather than by walking every record: the index names
// 160 standard library advisories out of the 4134 published, so this opens 160 files instead
// of 4134.
//
// A record the index names but the cache does not hold is skipped rather than failing the
// read. A truncated copy should narrow the answer, not refuse to give one -- and the caller
// treats an empty result as "nothing known", which is the same posture.
func stdlibWindows(dir string) ([]window, error) {
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

	var found []window
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
				log.WithFields(log.Fields{"advisory": v.ID, "error": err}).
					Debug("Advisory named by the index is not in the cache")
				continue
			}
			var a osvAdvisory
			if err := json.Unmarshal(record, &a); err != nil {
				log.WithFields(log.Fields{"advisory": v.ID, "error": err}).
					Debug("Could not read an advisory")
				continue
			}
			found = append(found, a.windows()...)
		}
	}
	return found, nil
}
