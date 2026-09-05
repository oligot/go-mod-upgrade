package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"golang.org/x/mod/modfile"

	"github.com/oligot/go-mod-upgrade/internal/cooldown"
	"github.com/oligot/go-mod-upgrade/internal/discover"
	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/prompt"
)

type AppEnv struct {
	Verbose  bool
	Force    bool
	List     bool
	PageSize int
	Hook     string
	Ignore   []string
	Cooldown string
}

func (app *AppEnv) Run() error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	ignore, err := discover.CompileIgnore(app.Ignore)
	if err != nil {
		return err
	}
	var window time.Duration
	if app.Cooldown != "" {
		window, err = cooldown.ParseDuration(app.Cooldown)
		if err != nil {
			return err
		}
		log.WithField("cooldown", window).Debug("Cooldown window")
	}
	// Deliberately not routed through discover.Exec: that sets GOWORK=off,
	// which would make this always report "off" and break workspace detection.
	gw, err := exec.Command("go", "env", "GOWORK").Output()
	if err != nil {
		return err
	}
	gowork := strings.TrimSpace(string(gw))
	paths, err := workspacePaths(gowork)
	if err != nil {
		return err
	}

	for _, path := range paths {
		dir := path
		if !filepath.IsAbs(path) {
			dir = filepath.Join(filepath.Dir(gowork), path)
		}
		log.WithField("dir", dir).Info("Using directory")
		if err := app.runDir(dir, ignore, window); err != nil {
			// Ctrl+C means stop the whole walk, not just this module: handle
			// the abort here rather than inside runDir.
			if errors.Is(err, prompt.ErrAborted) {
				log.Info("Bye")
				return nil
			}
			return err
		}
	}
	return nil
}

// workspacePaths returns the module directories to walk: the current directory
// outside workspace mode, every `use` entry of the go.work file inside it.
func workspacePaths(gowork string) ([]string, error) {
	if gowork == "" || gowork == "off" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		return []string{cwd}, nil
	}
	log.WithField("gowork", gowork).Info("Workspace mode")
	content, err := os.ReadFile(gowork)
	if err != nil {
		return nil, err
	}
	work, err := modfile.ParseWork("go.work", content, nil)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, use := range work.Use {
		if use != nil {
			paths = append(paths, use.Path)
		}
	}
	return paths, nil
}

// runDir discovers and updates the modules of one module directory.
func (app *AppEnv) runDir(dir string, ignore []*regexp.Regexp, window time.Duration) error {
	d := discover.Discoverer{Run: discover.Exec, Dir: dir, Ignore: ignore}
	modules, err := withSpinner(" Discovering modules...", d.Modules)
	if err != nil {
		return err
	}
	// Asked per directory: workspace members can pin different toolchains.
	supported, err := d.ToolsSupported()
	if err != nil {
		return err
	}
	log.WithFields(log.Fields{
		"dir":       dir,
		"supported": supported,
	}).Debug("Tool support")
	if supported {
		toolModules, err := withSpinner(" Discovering tool modules...", d.Tools)
		if err != nil {
			return err
		}
		modules = append(modules, toolModules...)
	}

	var held []cooldown.Held
	if window > 0 {
		modules, held = cooldown.Filter(modules, window, time.Now(), d.Versions)
		printHeld(held, window)
	}

	if len(modules) == 0 {
		// Everything held back by cooldown is not the same as everything being
		// up to date, and printHeld has already said so.
		if len(held) == 0 {
			fmt.Println("All modules are up to date")
		}
		return nil
	}
	if app.List {
		listModules(modules)
		return nil
	}
	if app.Force {
		log.Debug("Update all modules in non-interactive mode...")
		return update(dir, modules, app.Hook)
	}
	selected, err := prompt.Choose(modules, app.PageSize)
	if err != nil {
		return err
	}
	return update(dir, selected, app.Hook)
}

// withSpinner runs fn behind the discovery spinner and clears the line
// afterwards, the way the discovery functions used to do inline.
func withSpinner[T any](suffix string, fn func() (T, error)) (T, error) {
	var zero T
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return zero, err
	}
	s.Suffix = suffix
	s.Start()

	result, err := fn()

	s.Stop()
	// Clear line
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))
	return result, err
}

// printHeld reports the modules whose updates the cooldown window withheld, so
// that they don't disappear from the output silently.
func printHeld(held []cooldown.Held, window time.Duration) {
	if len(held) == 0 {
		return
	}
	plural := "s"
	if len(held) == 1 {
		plural = ""
	}
	c := color.New(color.FgYellow).SprintFunc()
	header := fmt.Sprintf("%d module%s held back by cooldown (%s):", len(held), plural, module.FormatAge(window))
	if _, err := fmt.Fprintf(color.Output, "%s\n", c(header)); err != nil {
		log.WithError(err).Error("Error while printing held back modules")
		return
	}
	for _, h := range held {
		if _, err := fmt.Fprintf(color.Output, "  %s %s (%s old)\n", h.Name, h.Version, module.FormatAge(h.Age)); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  h.Name,
			}).Error("Error while printing held back module")
		}
	}
}

func listModules(modules []module.Module) {
	maxName, maxFrom := module.MaxWidths(modules)
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		_, err := fmt.Fprintf(color.Output, "%s %s -> %s%s\n", x.FormatName(maxName), from, x.FormatTo(), x.FormatCooldown())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while listing module")
		}
	}
}

func update(dir string, modules []module.Module, hook string) error {
	for _, x := range modules {
		_, err := fmt.Fprintf(color.Output, "Updating %s to version %s...\n", x.FormatName(len(x.Name)), x.FormatTo())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while updating module")
		}
		// The version is pinned rather than left to `go get <module>`: the bare
		// form means @upgrade, which resolves to the latest release and would
		// install the very version cooldown withheld.
		//
		// Deliberately not routed through discover.Exec: `go get` runs without
		// GOWORK=off today, and setting it would be a silent behaviour change.
		get := exec.Command("go", "get", x.Name+"@"+x.To.Original())
		get.Dir = dir
		out, err := get.CombinedOutput()
		if err != nil {
			// Logged, not fatal: the remaining modules still get their turn.
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
				"out":   string(out),
			}).Error("Error while updating module")
		}
		if hook != "" {
			// cmd.Dir reproduces both halves of the old os.Chdir behaviour: the
			// child's cwd is the module directory, and a relative hook path
			// resolves against that directory.
			cmd := exec.Command(
				hook,
				x.Name,
				x.From.String(),
				x.To.String(),
			)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("hook %s: %w: %s", hook, err, strings.TrimSpace(string(out)))
			}
			log.Info(string(out))
		}
	}
	return nil
}
