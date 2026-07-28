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
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Update   *struct {
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
	// Progress belongs on stderr: stdout carries the listing, which may be
	// machine-readable and redirected to a file.
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond,
		spinner.WithWriter(os.Stderr))
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " " + message
	s.Start()
	return sync.OnceFunc(func() {
		s.Stop()
		// Clear line
		// Clear the line and leave the cursor at its start, so a message
		// printed next begins at column zero and can be matched by a tool
		// reading the output.
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))
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
		return nil, nil, fmt.Errorf("error reading go.mod in %q: %w", dir, err)
	}

	reqs, skip, err = parseRequirements(out)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing go.mod in %q: %w", dir, err)
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

// scope selects which of a module's dependencies are offered.
type scope int

const (
	// scopeDirect offers only the dependencies imported directly.
	scopeDirect scope = iota
	// scopeIndirect also offers the indirect requirements recorded in go.mod.
	scopeIndirect
	// scopeAll offers the whole module graph, including modules reached only
	// through other modules and so absent from go.mod.
	scopeAll
)

// graph lists every module in the build list of the module in dir, which
// reaches beyond the requirements recorded in its go.mod.
func graph(ctx context.Context, dir string) ([]requirement, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-e", "-json", "all")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running go command to list the module graph: %w", err)
	}
	return parseGraph(out)
}

// parseGraph interprets the output of "go list -m -json all".
func parseGraph(out []byte) ([]requirement, error) {
	var reqs []requirement
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var l listed
		if err := dec.Decode(&l); err != nil {
			return nil, fmt.Errorf("error parsing go list output: %w", err)
		}
		// The module being worked on carries no version and cannot be
		// upgraded; nor can one whose version could not be determined.
		if l.Main || l.Version == "" {
			continue
		}
		reqs = append(reqs, requirement{
			Path:     l.Path,
			Version:  l.Version,
			Indirect: l.Indirect,
		})
	}
	return reqs, nil
}

// discoverModules returns the modules in dir that have a newer version
// available, limited to the given scope.
func discoverModules(ctx context.Context, dir string, ignoreNames []string, sc scope) ([]module.Module, error) {
	stop, err := progress("Discovering modules...")
	if err != nil {
		return nil, err
	}
	defer stop()

	// Both sources report versions, but only go.mod distinguishes a direct
	// requirement from an indirect one, and only it records replacements.
	reqs, skip, err := requirements(ctx, dir)
	if err != nil {
		return nil, err
	}
	if sc == scopeAll {
		declared := make(map[string]bool, len(reqs))
		for _, r := range reqs {
			declared[r.Path] = true
		}
		all, err := graph(ctx, dir)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if !declared[r.Path] {
				reqs = append(reqs, r)
			}
		}
	}

	wanted := make([]requirement, 0, len(reqs))
	for _, r := range reqs {
		if skip[r.Path] {
			continue
		}
		if r.Indirect && sc == scopeDirect {
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
		// A module matching --ignore is kept and marked rather than dropped:
		// it must still reach a policy, which is where an exemption belongs.
		ignored := shouldIgnore(r.Path, r.Version, to, ignoreNames)
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
			Ignored:  ignored,
		})
	}
	// Clear the spinner before the caller starts printing, so its trailing
	// blanks do not end up on the first line of the listing.
	stop()
	return modules, nil
}
