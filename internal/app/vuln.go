package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
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

// scanVulnerabilities reports the known vulnerabilities affecting the modules
// in dir, keyed by module path.
//
// The scan runs in this process rather than as a subprocess, so a failure
// arrives as an error rather than an exit status. Callers must not read a
// failure as an absence of vulnerabilities: when the packages cannot be loaded
// the scan yields no findings at all, which is indistinguishable from a clean
// result.
func scanVulnerabilities(ctx context.Context, dir string) (vulnerabilities, error) {
	stop, err := progress("Scanning for vulnerabilities...")
	if err != nil {
		return nil, err
	}
	defer stop()

	var out bytes.Buffer
	args := []string{"-format", "json", "-C", dir}
	// Scanning against a local copy keeps the database out of the network path
	// on every run, and lets a scan work offline. A cache that cannot be
	// prepared is not fatal: the scan falls back to the published database.
	if db, err := vulndbCache(ctx); err != nil {
		log.WithError(err).Warn("Could not cache the vulnerability database, using the published one")
	} else {
		args = append(args, "-db", "file://"+filepath.ToSlash(db))
	}
	args = append(args, "./...")

	cmd := scan.Command(ctx, args...)
	cmd.Stdout = &out
	// govulncheck writes package loading diagnostics straight to the terminal
	// rather than to this writer, so there is nothing to relay from here.
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting vulnerability scan: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error scanning for vulnerabilities in %q: %w", dir, err)
	}

	vulns, err := parseVulnerabilities(out.Bytes())
	if err != nil {
		return nil, err
	}
	stop()
	return vulns, nil
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
		for _, t := range f.Trace {
			if t.Module == "" {
				continue
			}
			k := key{t.Module, f.OSV}
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
			if t.Package != "" {
				v.Called = true
			}
			merged[k] = v
		}
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
		ids := make([]string, 0, len(found))
		for _, v := range found {
			ids = append(ids, v.CVE())
			if v.Called {
				modules[i].VulnCalled = true
			}
			// The listing has room only for the identifier, so the rest is
			// left to verbose output.
			log.WithFields(log.Fields{
				"module":   modules[i].Name,
				"advisory": v.ID,
				"aliases":  strings.Join(v.Aliases, ", "),
				"fixed_in": v.FixedIn,
				"reached":  v.Called,
				"url":      v.URL,
			}).Debug("Vulnerability")
		}
		modules[i].Vulns = ids
	}
}
