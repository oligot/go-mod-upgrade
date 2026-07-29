package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"golang.org/x/mod/modfile"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// requires reports what one candidate version of a module asks of others, keyed
// by the required module path.
type requires map[string]string

// candidate is a module at the version an upgrade would move it to.
type candidate struct {
	Path    string
	Version string
}

// resolvers works out which upgrades would fix an advisory as a side effect.
//
// Go resolves a build with minimal version selection, taking the highest version
// any module asks for. So upgrading a dependent lifts a vulnerable module only
// when the dependent's own go.mod asks for a version at or past the fix --
// upgrading it otherwise leaves the advisory in place, and suggesting it would
// be a fix that cannot work.
//
// The answer is per advisory rather than per module, since two advisories in one
// module may be fixed in different releases.
func resolvers(ctx context.Context, dir string, modules []module.Module, vulns vulnerabilities) (map[string][]string, error) {
	// The modules carrying an advisory, and the version each needs to reach.
	needed := map[string]*semver.Version{}
	for _, mod := range modules {
		for _, v := range vulns[mod.Name] {
			at, err := semver.NewVersion(strings.TrimPrefix(v.FixedIn, toolchainPrefix))
			if err != nil {
				// An advisory with no fix cannot be resolved by any upgrade.
				continue
			}
			// Two advisories in one module may be fixed in different releases,
			// and only an upgrade clearing the highest resolves them all.
			if was, ok := needed[mod.Name]; !ok || at.GreaterThan(was) {
				needed[mod.Name] = at
			}
		}
	}
	if len(needed) == 0 {
		return nil, nil
	}

	// Only a module with an upgrade available can lift anything, and only the
	// version it would move to matters.
	var wanted []candidate
	for _, mod := range modules {
		if mod.From.Equal(mod.To) {
			continue
		}
		if _, carries := needed[mod.Name]; carries {
			// A module upgrading past its own fix is the direct fix, which is
			// already what the listing suggests.
			continue
		}
		wanted = append(wanted, candidate{Path: mod.Name, Version: "v" + mod.To.String()})
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	asks, err := candidateRequires(ctx, dir, wanted)
	if err != nil {
		return nil, err
	}
	return whatFixes(needed, asks), nil
}

// whatFixes reports, for each module needing to reach a version, the candidates
// whose own requirements would carry it there.
//
// needed maps a module path to the version fixing its advisories, and asks maps
// a candidate path to what that candidate requires. A candidate qualifies when it
// requires the module at or above the fix: Go takes the highest version asked
// for, so such an upgrade resolves the advisory without the module being named.
func whatFixes(needed map[string]*semver.Version, asks map[string]requires) map[string][]string {
	fixed := map[string][]string{}
	for from, wants := range asks {
		for path, at := range needed {
			want, ok := wants[path]
			if !ok {
				continue
			}
			has, err := semver.NewVersion(want)
			if err != nil {
				// A requirement we cannot read resolves nothing, rather than
				// being assumed to resolve everything.
				continue
			}
			if !has.LessThan(at) {
				fixed[path] = append(fixed[path], from)
			}
		}
	}
	// Sorted, so a listing does not shuffle between runs.
	for path := range fixed {
		slices.Sort(fixed[path])
	}
	return fixed
}

// candidateRequires reads what each candidate requires, keyed by candidate path.
//
// The go.mod of a published version is immutable and Go's module cache already
// stores it, so this needs no cache of its own. "go list -m" is what reads it
// without also fetching the module zip, which "go mod download" would.
func candidateRequires(ctx context.Context, dir string, wanted []candidate) (map[string]requires, error) {
	asks := make(map[string]requires, len(wanted))
	for chunk := range slices.Chunk(wanted, queryChunk) {
		args := []string{"list", "-m", "-e", "-json"}
		for _, c := range chunk {
			args = append(args, c.Path+"@"+c.Version)
		}
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("error running go command to read requirements: %w", err)
		}
		if err := parseCandidates(out, asks); err != nil {
			return nil, err
		}
	}
	return asks, nil
}

// parseCandidates reads the go.mod each listed candidate points at.
func parseCandidates(out []byte, asks map[string]requires) error {
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var l listed
		if err := dec.Decode(&l); err != nil {
			return fmt.Errorf("error parsing go list output: %w", err)
		}
		if l.Error != nil || l.GoMod == "" {
			// A version that cannot be resolved tells us nothing about what it
			// would require, so it simply resolves nothing.
			continue
		}
		body, err := os.ReadFile(l.GoMod)
		if err != nil {
			log.WithFields(log.Fields{
				"module": l.Path,
				"path":   l.GoMod,
				"error":  err,
			}).Debug("Could not read a candidate's go.mod")
			continue
		}
		asks[l.Path] = parseRequires(l.GoMod, body)
	}
	return nil
}

// parseRequires reads the require block of a go.mod body.
//
// ParseLax is used rather than Parse: a dependency may have been written for a
// newer Go than this build knows, and an unknown directive is no reason to give
// up on the requirements we came for.
func parseRequires(name string, body []byte) requires {
	f, err := modfile.ParseLax(name, body, nil)
	if err != nil {
		log.WithFields(log.Fields{
			"path":  name,
			"error": err,
		}).Debug("Could not parse a candidate's go.mod")
		return nil
	}
	asks := make(requires, len(f.Require))
	for _, r := range f.Require {
		asks[r.Mod.Path] = r.Mod.Version
	}
	return asks
}

// annotateResolvers records the resolution relation on both ends.
//
// A vulnerable module learns which upgrades would fix it, and each of those
// upgrades learns what it would fix. The second direction is what makes a listing
// actionable: the row to take is the one advertising that it clears a finding,
// not the row reporting the finding.
func annotateResolvers(modules []module.Module, fixed map[string][]string) {
	// Which advisories each candidate would resolve, the inverse of fixed.
	fixes := map[string][]string{}
	for path, by := range fixed {
		for _, from := range by {
			fixes[from] = append(fixes[from], path)
		}
	}
	for from := range fixes {
		slices.Sort(fixes[from])
	}

	for i := range modules {
		if by := fixed[modules[i].Name]; len(by) > 0 {
			modules[i].FixedBy = by
		}
		if what := fixes[modules[i].Name]; len(what) > 0 {
			modules[i].Fixes = what
		}
	}
}
