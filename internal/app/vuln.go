package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/rs/zerolog/log"
	"golang.org/x/vuln/scan"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// vulnerability is what is known about one advisory affecting a module.
type vulnerability struct {
	// ID is the Go advisory identifier, such as GO-2026-5970.
	ID string
	// Aliases holds the identifiers this advisory is also known by, such as
	// CVE and GHSA numbers.
	Aliases []string
	// FixedIn is the earliest version carrying the fix, empty if none.
	FixedIn string
	// URL points at the advisory.
	URL string
	// Called reports whether this code reaches the vulnerable code, rather
	// than merely depending on the module containing it.
	Called bool
}

// CVE returns the first CVE this advisory is known by, or its Go identifier if
// it has none.
func (v vulnerability) CVE() string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// vulnerabilities maps a module path to the advisories affecting it.
type vulnerabilities map[string][]vulnerability

// stdlibModule is the module path govulncheck uses for the standard library.
//
// It is not a module anything requires, so an advisory against it belongs to the
// toolchain rather than to a dependency, and is reported against the go
// directive instead.
const stdlibModule = "stdlib"

// toolchainPrefix is what Go puts in front of a version to name a toolchain, as
// in "go1.25.9". A toolchain directive and the fixed version of a standard
// library advisory both carry it, and neither parses as semver until it is
// removed.
const toolchainPrefix = "go"

// osvRecord mirrors the parts of an OSV advisory that we read.
//
// The Go vulnerability database leaves the OSV severity field empty, so there
// is no score to report; the aliases are what connect an advisory to the CVE
// numbering people recognise.
type osvRecord struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases"`
	Summary          string   `json:"summary"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

// findingRecord mirrors the parts of a govulncheck finding that we read.
type findingRecord struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module  string `json:"module"`
		Version string `json:"version"`
		Package string `json:"package"`
	} `json:"trace"`
}

// message is one entry of the govulncheck JSON stream.
type message struct {
	OSV      *osvRecord     `json:"osv"`
	Finding  *findingRecord `json:"finding"`
	SBOM     *struct{}      `json:"SBOM"`
	Progress *struct{}      `json:"progress"`
}

// reportedVulndb keeps the cache location from being repeated once per module
// of a workspace, since it is the same for all of them.
var reportedVulndb sync.Once

// reportVulndb names the database a scan reads, once per run, and says how old the
// advice in it is.
//
// Two ages, because they answer different questions and can disagree by a fortnight.
// The snapshot is when the advisories were published upstream, which is what decides
// whether an advisory filed last week is in this copy. cached is how long this
// machine has held the copy, which is what decides whether another fetch would find
// a newer one. A copy downloaded an hour ago can carry a two-week-old snapshot, and
// reporting only the local age would call that current.
//
// A snapshot that cannot be read leaves both age fields off rather than reporting
// zero, which would claim the advice was published this instant.
func reportVulndb(dir string) {
	reportedVulndb.Do(func() {
		entry := log.Debug().Str("path", dir)
		if at, err := snapshot(dir); err != nil {
			entry = entry.AnErr("snapshot_error", err)
		} else {
			entry = entry.
				Str("snapshot", at.UTC().Format(time.RFC3339)).
				Str("snapshot_age", since(at).String())
		}
		// When this machine last took a copy, which the directory's own timestamp
		// records: unpack writes it and nothing rewrites it afterwards.
		if info, err := os.Stat(dir); err == nil {
			entry = entry.Str("cached", since(info.ModTime()).String())
		}
		entry.Msg("Vulnerability database")
	})
}

// since is how long ago an instant was, as a cacheAge.
//
// Clamped at zero, as the listing's own ages are: a clock that moved backwards or a
// file dated in the future would otherwise report a negative age, which reads as
// something yet to happen.
func since(at time.Time) cacheAge {
	if at.IsZero() {
		return cacheAge{}
	}
	return cacheAge{of: max(time.Since(at), 0), known: true}
}

// scanVulnerabilities reports the known vulnerabilities affecting the modules
// in dir, keyed by module path.
//
// The scan runs in this process rather than as a subprocess, so a failure
// arrives as an error rather than an exit status. Callers must not read a
// failure as an absence of vulnerabilities: when the packages cannot be loaded
// the scan yields no findings at all, which is indistinguishable from a clean
// result.
func scanVulnerabilities(ctx context.Context, dir string, f tagFilter, caching bool) (vulnerabilities, error) {
	args := []string{"-format", "json", "-C", dir}
	// Scanning against a local copy keeps the database out of the network path
	// on every run, and lets a scan work offline. A cache that cannot be
	// prepared is not fatal: the scan falls back to the published database.
	var cache, etag string
	if db, err := preparedVulndb(ctx); err != nil {
		log.Warn().Err(err).Msg("Could not cache the vulnerability database, using the published one")
	} else {
		// The cache location varies by platform, so name the one in use.
		reportVulndb(db)
		args = append(args, "-db", "file://"+filepath.ToSlash(db))
		// The database is unpacked into a directory named by its etag, so the copy in
		// use identifies itself: a new database is a new directory and a new key.
		cache, etag = filepath.Dir(db), filepath.Base(db)
	}
	// A build tag decides which files compile, and so which vulnerable code the
	// build can reach at all.
	tags := f.tagArgs()
	if len(tags) > 0 {
		args = append(args, tags...)
	}
	args = append(args, "./...")

	// A scan takes tens of seconds on a real tree, and its answer is decided entirely by
	// inputs that can be hashed. Reusing it is only safe while every one of them is
	// unchanged, which is what the key covers -- including the project's own source, since
	// the scan reports reachability rather than mere presence.
	key := ""
	if cache != "" && caching {
		if k, err := scanKey(dir, tags, etag, toolchainVersion()); err != nil {
			log.Trace().Err(err).Msg("Could not key the scan, so not reusing one")
		} else {
			key = k
			if found, ok := loadScan(cache, key); ok {
				log.Trace().Fields(map[string]any{"dir": dir, "advisories": len(found)}).Msg("Reusing a scan, the sources and database being unchanged")
				return found, nil
			}
		}
	}

	var out bytes.Buffer
	cmd := scan.Command(ctx, args...)
	cmd.Stdout = &out
	// Confined and workspace-free, as every "go" invocation here is. Left in workspace mode
	// the scan would read a sibling's pinned version while the listing reported this
	// module's own, so the tool would name an upgrade for a version it never scanned.
	cmd.Env = scanEnv()
	// govulncheck writes package loading diagnostics straight to the terminal
	// rather than to this writer, so there is nothing to relay from here.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting vulnerability scan: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error scanning for vulnerabilities in %q: %w", dir, err)
	}

	found, err := parseVulnerabilities(out.Bytes())
	if err != nil {
		return nil, err
	}
	if key != "" {
		// A failure to record is not a failure to scan: the answer is in hand, and the
		// next run pays for the scan again rather than being told the tree is broken.
		if err := storeScan(cache, key, found); err != nil {
			log.Trace().Err(err).Msg("Could not record the scan")
		}
	}
	return found, nil
}

// parseVulnerabilities interprets the govulncheck JSON stream.
func parseVulnerabilities(out []byte) (vulnerabilities, error) {
	// Advisories and the findings referring to them arrive as separate
	// messages, so both are collected before being joined.
	advisories := map[string]osvRecord{}
	var findings []findingRecord

	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var m message
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("error parsing govulncheck output: %w", err)
		}
		switch {
		case m.OSV != nil:
			advisories[m.OSV.ID] = *m.OSV
		case m.Finding != nil:
			findings = append(findings, *m.Finding)
		}
	}

	// A vulnerability reached through a package is reported alongside one
	// naming only the module, so the two are merged per module and advisory.
	type key struct{ module, osv string }
	merged := map[key]vulnerability{}
	for _, f := range findings {
		// govulncheck orders a trace from the vulnerable symbol outwards, so the
		// first element names the module actually carrying the defect and the
		// rest are the frames that call it. Blaming those too would flag a
		// module for a bug it does not have, and propose upgrading it as the
		// fix -- which cannot work, since the defect is elsewhere.
		if len(f.Trace) == 0 {
			continue
		}
		at := f.Trace[0]
		if at.Module == "" {
			continue
		}
		k := key{at.Module, f.OSV}
		v, ok := merged[k]
		if !ok {
			a := advisories[f.OSV]
			v = vulnerability{
				ID:      f.OSV,
				Aliases: a.Aliases,
				FixedIn: f.FixedVersion,
				URL:     a.DatabaseSpecific.URL,
			}
		}
		// Naming a package means the vulnerable code is reachable.
		if at.Package != "" {
			v.Called = true
		}
		merged[k] = v
	}

	vulns := vulnerabilities{}
	for k, v := range merged {
		vulns[k.module] = append(vulns[k.module], v)
	}
	for path, list := range vulns {
		// Reachable advisories first, then by identifier, so the listing is
		// stable and the most pressing entry survives truncation.
		slices.SortFunc(list, func(a, b vulnerability) int {
			if a.Called != b.Called {
				if a.Called {
					return -1
				}
				return 1
			}
			return strings.Compare(a.ID, b.ID)
		})
		vulns[path] = list
	}
	return vulns, nil
}

// mergeVulns folds the advisories found in one module into a set gathered
// across several, as a workspace requires.
//
// Members share dependencies, so the same advisory is normally reported by more
// than one. It is recorded once, and counts as reachable if any member reaches
// the vulnerable code.
func mergeVulns(into, from vulnerabilities) {
	for path, found := range from {
		existing := into[path]
		for _, v := range found {
			at := slices.IndexFunc(existing, func(e vulnerability) bool {
				return e.ID == v.ID
			})
			if at < 0 {
				existing = append(existing, v)
				continue
			}
			if v.Called {
				existing[at].Called = true
			}
		}
		into[path] = existing
	}
}

// annotateVulns records against each module the advisories affecting it, and
// reports what is known about them for the detail a listing cannot carry.
func annotateVulns(modules []module.Module, vulns vulnerabilities) {
	for i := range modules {
		found := vulns[modules[i].Name]
		if len(found) == 0 {
			continue
		}
		// Ordered before the identifiers are taken, so what a narrow column keeps
		// is what matters most. The database publishes no severity, so reachability
		// is the priority there is: one the code calls demands attention now, while
		// one merely present waits for an ordinary upgrade. The name breaks the tie,
		// govulncheck's own order being unspecified and so not reproducible.
		found = slices.SortedStableFunc(slices.Values(found), func(a, b vulnerability) int {
			if a.Called != b.Called {
				if a.Called {
					return -1
				}
				return 1
			}
			return strings.Compare(a.CVE(), b.CVE())
		})
		ids := make([]string, 0, len(found))
		for _, v := range found {
			ids = append(ids, v.CVE())
			if v.Called {
				modules[i].Reachable++
			}
			// The listing has room only for the identifier, so the rest is
			// left to verbose output.
			log.Trace().Fields(map[string]any{
				"module":   modules[i].Name,
				"advisory": v.ID,
				"aliases":  strings.Join(v.Aliases, ", "),
				"fixed_in": v.FixedIn,
				"reached":  v.Called,
				"url":      v.URL,
			}).Msg("Vulnerability")
		}
		modules[i].Vulns = ids
	}
}

// ToolchainName is the row a standard library advisory is reported against.
//
// The standard library is not a module anything requires, so an advisory in it
// has no entry in go.mod to attach to. It is shown as its own row, named for the
// directive that governs it, so that it appears in a listing and can be reached
// by a policy like anything else.
const ToolchainName = "go (toolchain)"

// toolchainModule returns the row carrying the standard library advisories, and
// whether there is one to report.
//
// from is the version go.mod declares and the advisories are measured against.
// The fix is the newest version any advisory names, since one toolchain release
// resolves every advisory fixed at or below it -- which is why this is a single
// row rather than one per advisory.
func toolchainModule(from string, vulns vulnerabilities) (module.Module, bool) {
	found := vulns[stdlibModule]
	if len(found) == 0 || from == "" {
		return module.Module{}, false
	}

	current, err := semver.NewVersion(from)
	if err != nil {
		// A go directive that is not a version is not something to reason
		// about, so the advisories are left to the log rather than guessed at.
		log.Trace().Fields(map[string]any{
			"version": from,
			"error":   err,
		}).Msg("Cannot read the go directive as a version")
		return module.Module{}, false
	}

	to := current
	ids := make([]string, 0, len(found))
	reachable := 0
	for _, v := range found {
		ids = append(ids, v.CVE())
		if v.Called {
			reachable++
		}
		log.Trace().Fields(map[string]any{
			"module":   stdlibModule,
			"advisory": v.ID,
			"aliases":  strings.Join(v.Aliases, ", "),
			"fixed_in": v.FixedIn,
			"reached":  v.Called,
			"url":      v.URL,
		}).Msg("Vulnerability")

		fixed, err := semver.NewVersion(strings.TrimPrefix(v.FixedIn, toolchainPrefix))
		if err != nil {
			continue
		}
		if fixed.GreaterThan(to) {
			to = fixed
		}
	}

	return module.Module{
		Name:      ToolchainName,
		From:      current,
		To:        to,
		Vulns:     ids,
		Reachable: reachable,
	}, true
}
