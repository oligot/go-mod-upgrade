package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/briandowns/spinner"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// queryChunk caps how many modules are passed to a single go list
// invocation, to keep the command line well clear of the system limit.
const queryChunk = 200

// progressOut is where a spinner draws, and where the log handler clears a line
// before writing, so the two are ordered against each other rather than
// interleaved.
//
// It belongs on stderr: stdout carries the listing, which may be machine-readable
// and redirected to a file.
var progressOut io.Writer = os.Stderr

// spinning holds the spinner currently drawing, if any, so a log entry can clear
// its line before writing. Guarded because entries are written from whichever
// goroutine logs, while a spinner redraws from its own.
var spinning struct {
	sync.Mutex
	at *spinner.Spinner
}

// draw starts a spinner and registers it as the one drawing, returning a function
// releasing it. Only one draws at a time, so a second replaces the first and
// restores it when it stops.
//
// Starting and registering belong together: a spinner declines to draw when the
// output is not a terminal, and one that is not drawing leaves no line for an
// entry to clear, so whether to register can only be answered after starting.
func draw(s *spinner.Spinner) (release func()) {
	s.Start()
	if !s.Active() {
		return func() {}
	}
	spinning.Lock()
	prev := spinning.at
	spinning.at = s
	spinning.Unlock()
	return func() {
		spinning.Lock()
		spinning.at = prev
		spinning.Unlock()
	}
}

// LogHandler wraps a handler so that an entry written while a spinner is drawing
// clears its line first.
//
// A spinner leaves the cursor part-way along a line, meaning to overwrite it by
// returning to column zero on its next tick. An entry written there joins it on
// that row. So the entry takes the spinner's own lock, which its redraw also
// holds, and clears the line before writing: the entry lands at column zero and
// the spinner redraws beneath it.
func LogHandler(h log.Handler) log.Handler { return quiet{h} }

// quiet is the handler LogHandler returns.
type quiet struct{ log.Handler }

func (q quiet) HandleLog(e *log.Entry) error {
	spinning.Lock()
	s := spinning.at
	spinning.Unlock()
	if s == nil {
		return q.Handler.HandleLog(e)
	}
	// Held across the write so a redraw cannot land between the clear and the
	// entry.
	s.Lock()
	defer s.Unlock()
	fmt.Fprint(progressOut, "\r\033[K")
	return q.Handler.HandleLog(e)
}

// requirement is one entry from the require block of a go.mod file.
type requirement struct {
	Path     string
	Version  string
	Indirect bool
}

// modFile mirrors the parts of "go mod edit -json" that we read.
type modFile struct {
	Module struct{ Path string }
	// Go is the language version the go directive names, such as "1.25.9". A
	// standard library advisory is reported against this rather than against a
	// module, since that is what has to move to resolve one.
	Go string
	// Toolchain names a specific toolchain when the file pins one, which then
	// decides the standard library in use rather than the go directive.
	Toolchain string
	Require   []struct {
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
	// Time is when this version was published. It says how long a release has had
	// to be found broken, which is what a cooldown weighs.
	Time   *time.Time
	Update *struct {
		Version string
		Time    *time.Time
	}
	// Deprecated carries the author's deprecation message, reported with -u. It
	// is a property of the module rather than of one version.
	Deprecated string
	// Retracted holds the author's reasons for withdrawing this version,
	// reported with -retracted. It is a property of the version in use.
	Retracted []string
	// GoMod is where the module cache holds this version's go.mod, which is what
	// says which versions it would require of others.
	GoMod string
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
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond,
		spinner.WithWriter(progressOut))
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " " + message
	release := draw(s)
	timing.Lock()
	started := timing.now()
	timing.Unlock()
	return sync.OnceFunc(func() {
		timing.Lock()
		took := timing.now().Sub(started)
		timing.Unlock()
		record(message, took)
		s.Stop()
		release()
		// Clear the line and leave the cursor at its start, so a message
		// printed next begins at column zero and can be matched by a tool
		// reading the output.
		fmt.Fprintf(progressOut, "\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))
	}), nil
}

// counter reports progress through work of a known size, so a caller waiting on
// several passes can see which one it is on.
//
// The count is held atomically because the passes run concurrently: each finishes
// whenever its own go list does, and the spinner is redrawn from its own
// goroutine.
type counter struct {
	done  atomic.Int64
	total int
	label string
	spin  *spinner.Spinner
	stop  func()
}

// track starts a spinner reporting completions out of total.
func track(label string, total int) (*counter, error) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond,
		spinner.WithWriter(progressOut))
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	c := &counter{total: total, label: label, spin: s}
	c.render()
	release := draw(s)
	timing.Lock()
	started := timing.now()
	timing.Unlock()
	c.stop = sync.OnceFunc(func() {
		timing.Lock()
		took := timing.now().Sub(started)
		timing.Unlock()
		// The passes ran at once inside this one bracket, so the count travels with the
		// elapsed time rather than being inferred from how often the phase appeared.
		recordPasses(label, took, max(total, 1))
		s.Stop()
		release()
		fmt.Fprintf(progressOut, "\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))
	})
	return c, nil
}

// step records one completed pass and redraws the label.
func (c *counter) step() {
	c.done.Add(1)
	c.render()
}

// render updates the spinner's label under its own lock, which is what makes
// this safe to call while it is spinning.
func (c *counter) render() {
	c.spin.Lock()
	c.spin.Suffix = fmt.Sprintf(" %s (%d/%d)", c.label, c.done.Load(), c.total)
	c.spin.Unlock()
}

// Stop clears the spinner. Calling it more than once is harmless.
func (c *counter) Stop() { c.stop() }

// declared is what a go.mod file says that we act on.
type declared struct {
	// Reqs are the entries of the require block.
	Reqs []requirement
	// Skip holds the modules replaced by a local filesystem path. Those have no
	// upstream version to query, so asking about them would fail.
	Skip map[string]struct{}
	// Go is the language version the go directive names, such as "1.25.9". A
	// standard library advisory is reported against this, since it is what has
	// to move to resolve one.
	Go string
	// Toolchain names a specific toolchain when the file pins one, which then
	// decides the standard library in use rather than the go directive.
	Toolchain string
}

// stdlibVersion returns the version the standard library advisories should be
// measured against, which is whichever of the two directives governs.
//
// A toolchain directive overrides the go directive when both are present, since
// it names the toolchain that will actually build the module.
func (d declared) stdlibVersion() string {
	if d.Toolchain != "" {
		return strings.TrimPrefix(d.Toolchain, toolchainPrefix)
	}
	return d.Go
}

// requirements reads the go.mod file in dir.
//
// The go.mod file is the authority on which modules a given module requires
// and whether it requires them directly. Unlike "go list -m all" it is
// unaffected by workspace mode, which reports the union of every workspace
// member's dependencies and so cannot attribute a requirement to one module.
func requirements(ctx context.Context, dir string) (declared, error) {
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json")
	cmd.Dir = dir
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return declared{}, fmt.Errorf("error reading go.mod in %q: %w", dir, err)
	}

	d, err := parseRequirements(out)
	if err != nil {
		return declared{}, fmt.Errorf("error parsing go.mod in %q: %w", dir, err)
	}
	return d, nil
}

// parseRequirements interprets the output of "go mod edit -json".
func parseRequirements(out []byte) (declared, error) {
	var parsed modFile
	if err := json.Unmarshal(out, &parsed); err != nil {
		return declared{}, err
	}

	d := declared{
		Skip:      map[string]struct{}{},
		Go:        parsed.Go,
		Toolchain: parsed.Toolchain,
	}
	for _, r := range parsed.Replace {
		// A replacement without a version points at a directory on disk.
		// See issue https://github.com/oligot/go-mod-upgrade/issues/55
		if r.New.Version == "" {
			log.WithFields(log.Fields{
				"module": r.Old.Path,
				"path":   r.New.Path,
			}).Debug("Skipping locally replaced module")
			d.Skip[r.Old.Path] = struct{}{}
		}
	}

	for _, r := range parsed.Require {
		d.Reqs = append(d.Reqs, requirement{
			Path:     r.Path,
			Version:  r.Version,
			Indirect: r.Indirect,
		})
	}
	return d, nil
}

// state is what the toolchain reports about one module beyond the version in
// use: whether a newer one exists, and whether the author has since disowned
// either the module or this version of it.
type state struct {
	// Update is the newest version available, empty when already at it.
	Update string
	// Deprecated is the author's deprecation message, empty when the module
	// carries none. It applies to the module rather than to one version.
	Deprecated string
	// Retracted holds the author's reasons for withdrawing the version in use,
	// empty when it stands. Unlike a deprecation this is per version, so an
	// upgrade can resolve it.
	Retracted []string
	// Released is when the version on offer was published, or when the version in
	// use was if there is nothing newer. Zero when the toolchain did not say, which
	// reads as unknown rather than as fresh.
	Released time.Time
}

// inspect reports what the toolchain knows about each requirement, keyed by
// module path.
//
// Modules are queried as path@version rather than by path alone. That form is
// resolved without reference to the main module's build list, so it works in a
// module whose go.sum is incomplete -- as workspace members often are, since
// the workspace resolves their dependencies collectively.
func inspect(ctx context.Context, dir string, reqs []requirement, upgrades bool) (map[string]state, error) {
	found := map[string]state{}
	for chunk := range slices.Chunk(reqs, queryChunk) {
		cmd := exec.CommandContext(ctx, "go", queryArgs(chunk, upgrades)...)
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
//
// -retracted is what makes a withdrawn version visible; without it the field is
// left empty and a retraction reads as an ordinary version.
func queryArgs(reqs []requirement, upgrades bool) []string {
	args := []string{"list", "-m", "-e", "-retracted", "-json"}
	if upgrades {
		// -u is what asks the proxy what has been published, and the only part of this
		// that touches the network. Dropped when a recent answer is in hand, since the
		// rest -- the versions, deprecations and retractions -- is read from the module
		// cache in a fiftieth of the time.
		args = append(args, "-u")
	}
	for _, r := range reqs {
		args = append(args, r.Path+"@"+r.Version)
	}
	return args
}

// parseUpdates interprets the output of "go list -m -u -retracted -json" and
// records what it says about each module in found.
func parseUpdates(out []byte, found map[string]state) error {
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
		s := state{Deprecated: l.Deprecated, Retracted: l.Retracted}
		// The version in use dates the module when there is nothing newer, so a
		// listing can say how old what it has is.
		if l.Time != nil {
			s.Released = *l.Time
		}
		if l.Update != nil && l.Update.Version != "" && l.Update.Version != l.Version {
			s.Update = l.Update.Version
			// What is on offer is what a cooldown weighs, so its date wins over the
			// date of what is installed.
			if l.Update.Time != nil {
				s.Released = *l.Update.Time
			}
		}
		found[l.Path] = s
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

// discoverModules returns the modules in dir, limited to the given scope, each
// carrying the newest version available, along with what go.mod declares.
//
// A module already at its newest version is returned with To equal to From
// rather than dropped. A policy has to see every module for an allow-list to
// mean anything, and a module with no upgrade available is precisely the one an
// advisory is worst in, since there is nothing to upgrade to. Listings filter
// on --show, which by default keeps only the modules with an upgrade.
//
// The declared directives are returned too, since a standard library advisory is
// reported against the toolchain rather than against any module here.
func discoverModules(ctx context.Context, dir string, ignoreNames []string, sc scope, cache, window string) ([]module.Module, declared, error) {
	stop, err := progress("Discovering modules...")
	if err != nil {
		return nil, declared{}, err
	}
	defer stop()

	// Both sources report versions, but only go.mod distinguishes a direct
	// requirement from an indirect one, and only it records replacements.
	mod, err := requirements(ctx, dir)
	if err != nil {
		return nil, declared{}, err
	}
	reqs := mod.Reqs
	if sc == scopeAll {
		named := make(map[string]struct{}, len(reqs))
		for _, r := range reqs {
			named[r.Path] = struct{}{}
		}
		all, err := graph(ctx, dir)
		if err != nil {
			return nil, declared{}, err
		}
		for _, r := range all {
			if _, ok := named[r.Path]; !ok {
				reqs = append(reqs, r)
			}
		}
	}

	wanted := make([]requirement, 0, len(reqs))
	for _, r := range reqs {
		if _, ok := mod.Skip[r.Path]; ok {
			continue
		}
		if r.Indirect && sc == scopeDirect {
			continue
		}
		wanted = append(wanted, r)
	}
	if len(wanted) == 0 {
		return nil, mod, nil
	}

	// What upgrades are available, from a recent answer when there is one. Only -u
	// touches the network, so a hit turns a second of waiting into a fiftieth.
	found, cached := loadUpgrades(cache, window, wanted)
	if !cached {
		var err error
		if found, err = inspect(ctx, dir, wanted, true); err != nil {
			return nil, declared{}, err
		}
		saveUpgrades(cache, window, wanted, found)
	} else {
		// The versions, deprecations and retractions still come from the module cache,
		// since those describe what is installed rather than what is published, and a
		// go.mod edited since would otherwise be reported against the old requirements.
		local, err := inspect(ctx, dir, wanted, false)
		if err != nil {
			return nil, declared{}, err
		}
		found = mergeUpgrades(local, found)
	}

	modules, err := assemble(wanted, found, ignoreNames)
	if err != nil {
		return nil, declared{}, err
	}
	// Clear the spinner before the caller starts printing, so its trailing
	// blanks do not end up on the first line of the listing.
	stop()
	return modules, mod, nil
}

// assemble pairs each requirement with what the toolchain reports about it.
//
// A requirement with no newer version is kept, standing where it is, rather than
// dropped: a policy has to see every module for an allow-list to mean anything,
// and a module with nothing to upgrade to is the worst case for an advisory
// rather than the safest.
func assemble(wanted []requirement, found map[string]state, ignoreNames []string) ([]module.Module, error) {
	modules := []module.Module{}
	for _, r := range wanted {
		s := found[r.Path]
		// A module already at its newest version stands at the one it holds.
		to := s.Update
		if to == "" {
			to = r.Version
		}
		log.WithFields(log.Fields{
			"name":       r.Path,
			"from":       r.Version,
			"to":         to,
			"indirect":   r.Indirect,
			"deprecated": s.Deprecated != "",
			"retracted":  len(s.Retracted) > 0,
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
			Name:       r.Path,
			From:       fromversion,
			To:         toversion,
			Indirect:   r.Indirect,
			Ignored:    ignored,
			Deprecated: s.Deprecated,
			Retracted:  s.Retracted,
			Released:   s.Released,
		})
	}
	return modules, nil
}
