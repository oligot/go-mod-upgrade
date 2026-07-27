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
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/briandowns/spinner"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// queryChunk caps how many modules are passed to a single go list
// invocation, to keep the command line well clear of the system limit.
const queryChunk = 200

// requirement is one entry from the require block of a go.mod file.
type requirement struct {
	Path     string
	Version  string
	Indirect bool
}

// modFile mirrors the parts of "go mod edit -json" that we read.
type modFile struct {
	Module  struct{ Path string }
	Require []struct {
		Path     string
		Version  string
		Indirect bool
	}
	Replace []struct {
		Old struct{ Path string }
		New struct {
			Path    string
			Version string
		}
	}
}

// listed mirrors the parts of "go list -m -json" that we read.
type listed struct {
	Path    string
	Version string
	Update  *struct {
		Version string
	}
	Error *struct {
		Err string
	}
}

// progress shows a spinner labelled message until the returned stop function
// is called, which stops it and clears the line.
//
// stop follows the same convention as context.CancelFunc: calling it more than
// once is harmless, so callers can defer it to cover the error paths and still
// call it early to stop the spinner before writing their own output.
func progress(message string) (stop func(), err error) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " " + message
	s.Start()
	return sync.OnceFunc(func() {
		s.Stop()
		// Clear line
		fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))
	}), nil
}

// requirements reads the require block of the go.mod file in dir.
//
// The go.mod file is the authority on which modules a given module requires
// and whether it requires them directly. Unlike "go list -m all" it is
// unaffected by workspace mode, which reports the union of every workspace
// member's dependencies and so cannot attribute a requirement to one module.
//
// The returned skip set holds modules replaced by a local filesystem path.
// Those have no upstream version to query, so asking about them would fail.
func requirements(ctx context.Context, dir string) (reqs []requirement, skip map[string]bool, err error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json")
	cmd.Dir = dir
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("error reading go.mod in %s: %w", dir, err)
	}

	reqs, skip, err = parseRequirements(out)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing go.mod in %s: %w", dir, err)
	}
	return reqs, skip, nil
}

// parseRequirements interprets the output of "go mod edit -json".
func parseRequirements(out []byte) (reqs []requirement, skip map[string]bool, err error) {
	var parsed modFile
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, nil, err
	}

	skip = map[string]bool{}
	for _, r := range parsed.Replace {
		// A replacement without a version points at a directory on disk.
		// See issue https://github.com/oligot/go-mod-upgrade/issues/55
		if r.New.Version == "" {
			log.WithFields(log.Fields{
				"module": r.Old.Path,
				"path":   r.New.Path,
			}).Debug("Skipping locally replaced module")
			skip[r.Old.Path] = true
		}
	}

	for _, r := range parsed.Require {
		reqs = append(reqs, requirement{
			Path:     r.Path,
			Version:  r.Version,
			Indirect: r.Indirect,
		})
	}
	return reqs, skip, nil
}

// updates reports the newest version available for each requirement, keyed by
// module path. Modules already at the newest version are absent from the map.
//
// Modules are queried as path@version rather than by path alone. That form is
// resolved without reference to the main module's build list, so it works in a
// module whose go.sum is incomplete -- as workspace members often are, since
// the workspace resolves their dependencies collectively.
func updates(ctx context.Context, dir string, reqs []requirement) (map[string]string, error) {
	found := map[string]string{}
	for chunk := range slices.Chunk(reqs, queryChunk) {
		cmd := exec.CommandContext(ctx, "go", queryArgs(chunk)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("error running go command to discover modules: %w", err)
		}
		if err := parseUpdates(out, found); err != nil {
			return nil, err
		}
	}
	return found, nil
}

// queryArgs builds the go list invocation for a batch of requirements.
func queryArgs(reqs []requirement) []string {
	args := []string{"list", "-m", "-u", "-e", "-json"}
	for _, r := range reqs {
		args = append(args, r.Path+"@"+r.Version)
	}
	return args
}

// parseUpdates interprets the output of "go list -m -u -json" and records any
// newer versions in found.
func parseUpdates(out []byte, found map[string]string) error {
	// The objects are concatenated rather than wrapped in an array.
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var l listed
		if err := dec.Decode(&l); err != nil {
			return fmt.Errorf("error parsing go list output: %w", err)
		}
		// -e reports a failed lookup in the object instead of exiting
		// non-zero, so one unreachable module cannot hide the rest.
		if l.Error != nil {
			log.WithFields(log.Fields{
				"module": l.Path,
				"error":  l.Error.Err,
			}).Warn("Could not check module for updates")
			continue
		}
		if l.Update != nil && l.Update.Version != "" && l.Update.Version != l.Version {
			found[l.Path] = l.Update.Version
		}
	}
	return nil
}

// discoverModules returns the modules in dir that have a newer version
// available. Indirect requirements are included only when indirect is set.
func discoverModules(ctx context.Context, dir string, ignoreNames []string, indirect bool) ([]module.Module, error) {
	stop, err := progress("Discovering modules...")
	if err != nil {
		return nil, err
	}
	defer stop()

	reqs, skip, err := requirements(ctx, dir)
	if err != nil {
		return nil, err
	}

	wanted := make([]requirement, 0, len(reqs))
	for _, r := range reqs {
		if skip[r.Path] {
			continue
		}
		if r.Indirect && !indirect {
			continue
		}
		wanted = append(wanted, r)
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	found, err := updates(ctx, dir, wanted)
	if err != nil {
		return nil, err
	}

	modules := []module.Module{}
	for _, r := range wanted {
		to, ok := found[r.Path]
		if !ok {
			continue
		}
		log.WithFields(log.Fields{
			"name":     r.Path,
			"from":     r.Version,
			"to":       to,
			"indirect": r.Indirect,
		}).Debug("Found module")
		if shouldIgnore(r.Path, r.Version, to, ignoreNames) {
			continue
		}
		fromversion, err := semver.NewVersion(r.Version)
		if err != nil {
			return nil, err
		}
		toversion, err := semver.NewVersion(to)
		if err != nil {
			return nil, err
		}
		modules = append(modules, module.Module{
			Name:     r.Path,
			From:     fromversion,
			To:       toversion,
			Indirect: r.Indirect,
		})
	}
	// Clear the spinner before the caller starts printing, so its trailing
	// blanks do not end up on the first line of the listing.
	stop()
	return modules, nil
}
