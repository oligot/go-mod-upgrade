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
	NoMajor  bool
	NoCache  bool
}

func (app *AppEnv) Run() error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	ignore, err := discover.CompileIgnore(app.Ignore)
	if err != nil {
		return err
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
		if err := app.runDir(dir, ignore); err != nil {
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
func (app *AppEnv) runDir(dir string, ignore []*regexp.Regexp) error {
	d := discover.Discoverer{Run: discover.Exec, Dir: dir, Ignore: ignore}
	found, err := withSpinner(" Discovering modules...", func() (discovered, error) {
		modules, err := d.Modules()
		if err != nil {
			return discovered{}, err
		}
		if app.NoMajor {
			return discovered{modules: modules}, nil
		}
		major, logs := d.MajorUpgrades(app.NoCache)
		return discovered{modules: append(modules, major...), logs: logs}, nil
	})
	if err != nil {
		return err
	}
	// Held until the spinner has stopped: a log line drawn over it corrupts
	// the line.
	for _, logFn := range found.logs {
		logFn()
	}
	modules := found.modules
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

	if len(modules) == 0 {
		fmt.Println("All modules are up to date")
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

// discovered is what one discovery pass produces: the modules, plus the log
// lines that pass deferred until the spinner was gone.
type discovered struct {
	modules []module.Module
	logs    []func()
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

func listModules(modules []module.Module) {
	maxName, maxFrom := module.MaxWidths(modules)
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		_, err := fmt.Fprintf(color.Output, "%s %s -> %s\n", x.FormatName(maxName), from, x.FormatTo())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while listing module")
		}
	}
}

// runGo runs a go command in dir. Deliberately not routed through
// discover.Exec: the update commands run without GOWORK=off today, and setting
// it would be a silent behaviour change.
func runGo(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	return cmd.CombinedOutput()
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
		// The version is pinned rather than left to `go get <module>`: a major
		// upgrade resolves to a different module path, and the bare form would
		// pick that path's latest rather than the version offered.
		target := x.Name + "@" + x.To.Original()
		if out, err := runGo(dir, "get", target); err != nil {
			return fmt.Errorf("go get %s: %w: %s", target, err, strings.TrimSpace(string(out)))
		}

		if x.IsMajorUpgrade {
			// go.mod already requires the new major at this point, so a
			// failure below never leaves imports pointing at a missing module.
			if err := module.RewriteImportsInProject(dir, x.OldName, x.Name); err != nil {
				return fmt.Errorf("rewriting imports from %s to %s: %w", x.OldName, x.Name, err)
			}
			if out, err := runGo(dir, "get", x.OldName+"@none"); err != nil {
				return fmt.Errorf("go get %s@none: %w: %s", x.OldName, err, strings.TrimSpace(string(out)))
			}
			if out, err := runGo(dir, "mod", "tidy"); err != nil {
				return fmt.Errorf("go mod tidy: %w: %s", err, strings.TrimSpace(string(out)))
			}
			fmt.Printf("✅ Automatically upgraded imports and dependencies from '%s' to '%s'.\n", x.OldName, x.Name)
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
