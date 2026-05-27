package app

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"golang.org/x/mod/modfile"

	"github.com/oligot/go-mod-upgrade/internal/api"
	"github.com/oligot/go-mod-upgrade/internal/module"
)

// MultiSelect that doesn't show the answer
// It just reset the prompt and the answers are shown afterwards
type MultiSelect struct {
	survey.MultiSelect
}

func (m MultiSelect) Cleanup(config *survey.PromptConfig, val interface{}) error {
	return m.Render("", nil)
}

type AppEnv struct {
	Verbose  bool
	Force    bool
	List     bool
	PageSize int
	Hook     string
	Ignore   []string
	NoMajor  bool
}

func (app *AppEnv) Run() error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	var paths []string
	gw, err := exec.Command("go", "env", "GOWORK").Output()
	if err != nil {
		return err
	}
	gowork := strings.TrimSpace(string(gw))
	if gowork == "" || gowork == "off" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		paths = append(paths, cwd)
	} else {
		log.WithField("gowork", gowork).Info("Workspace mode")
		content, err := os.ReadFile(gowork)
		if err != nil {
			return err
		}
		work, err := modfile.ParseWork("go.work", content, nil)
		if err != nil {
			return err
		}
		for _, use := range work.Use {
			if use != nil {
				paths = append(paths, use.Path)
			}
		}
	}

	for _, path := range paths {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		dir := path
		if !filepath.IsAbs(path) {
			dir = filepath.Join(filepath.Dir(gowork), path)
		}
		log.WithField("dir", dir).Info("Using directory")
		if err := os.Chdir(dir); err != nil {
			return err
		}
		modules, err := discoverModules(app.Ignore, app.NoMajor)
		if err != nil {
			return err
		}
		supported, err := toolsSupported()
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"supported": supported,
		}).Debug("Tool support")
		if supported {
			toolModules, err := discoverTools(app.Ignore)
			if err != nil {
				return err
			}
			modules = append(modules, toolModules...)
		}
		if len(modules) > 0 {
			if app.List {
				listModules(modules)
			} else if app.Force {
				log.Debug("Update all modules in non-interactive mode...")
				if err := update(modules, app.Hook); err != nil {
					return err
				}
			} else {
				chosen, err := choose(modules, app.PageSize)
				if err != nil {
					return err
				}
				if err := update(chosen, app.Hook); err != nil {
					return err
				}
			}
		} else {
			fmt.Println("All modules are up to date")
		}
		if err := os.Chdir(cwd); err != nil {
			return err
		}
	}
	return nil
}

func discoverModules(ignoreNames []string, noMajor bool) ([]module.Module, error) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " Discovering modules..."
	s.Start()

	args := []string{
		"list",
		"-u",
		"-mod=readonly",
		"-f",
		"'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}'",
		"-m",
		"all",
	}

	cmd := exec.Command("go", args...)
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(os.Environ(), "GOWORK=off")
	list, err := cmd.Output()

	var (
		majorUpgrades []module.Module
		pendingLogs   []func()
	)
	if !noMajor {
		directDeps, depsErr := listDirectDependencies()
		if depsErr != nil {
			pendingLogs = append(pendingLogs, func() {
				log.WithError(depsErr).Warn("skipping major version check: failed to list direct dependencies")
			})
		} else {
			var fetchLogs []func()
			majorUpgrades, fetchLogs = fetchMajorUpgrades(directDeps)
			depsCount := len(directDeps)
			pendingLogs = append(pendingLogs, func() {
				log.WithField("count", depsCount).Debug("checked direct dependencies for major version upgrades")
			})
			pendingLogs = append(pendingLogs, fetchLogs...)
		}
	}

	s.Stop()
	// Clear line
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))

	for _, logFn := range pendingLogs {
		logFn()
	}

	if err != nil {
		return nil, fmt.Errorf("error running go command to discover modules: %w", err)
	}

	hasMajorUpgrade := make(map[string]bool)
	for _, up := range majorUpgrades {
		hasMajorUpgrade[up.OldName] = true
	}

	split := strings.Split(string(list), "\n")
	modules := []module.Module{}
	re := regexp.MustCompile(`'(.+): (.+) -> (.+)'`)
	for _, x := range split {
		if x != "''" && x != "" {
			matched := re.FindStringSubmatch(x)
			if len(matched) < 4 {
				return nil, fmt.Errorf("couldn't parse module %s", x)
			}
			name, from, to := matched[1], matched[2], matched[3]

			if hasMajorUpgrade[name] {
				continue
			}

			log.WithFields(log.Fields{
				"name": name,
				"from": from,
				"to":   to,
			}).Debug("Found module")
			if shouldIgnore(name, from, to, ignoreNames) {
				continue
			}
			fromversion, err := semver.NewVersion(from)
			if err != nil {
				return nil, err
			}
			toversion, err := semver.NewVersion(to)
			if err != nil {
				return nil, err
			}
			d := module.Module{
				Name: name,
				From: fromversion,
				To:   toversion,
			}
			modules = append(modules, d)
		}
	}

	for _, up := range majorUpgrades {
		if shouldIgnore(up.Name, up.From.String(), up.To.String(), ignoreNames) {
			continue
		}
		modules = append(modules, up)
	}

	return modules, nil
}

func discoverTools(ignoreNames []string) ([]module.Module, error) {

	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " Discovering tool modules..."
	s.Start()

	toolsArgs := []string{
		"list",
		"-f",
		"{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}",
		"tool",
	}
	cmd := exec.Command("go", toolsArgs...)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	toolsOutput, err := cmd.Output()

	s.Stop()
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))

	if err != nil {
		if strings.Contains(err.Error(), "matched no packages") {
			return []module.Module{}, nil
		}
		log.WithFields(log.Fields{
			"error": err,
			"args":  cmd.Args,
		}).Error("error listing tools")
		return nil, fmt.Errorf("error listing tools: %w", err)
	}

	var modules []module.Module
	tools := strings.Split(strings.TrimSpace(string(toolsOutput)), "\n")
	for _, tool := range tools {
		if tool == "" {
			continue
		}

		parts := strings.Fields(tool)
		if len(parts) == 1 {
			continue // local tool
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tool format: %s", tool)
		}
		toolPath, currentVersion := parts[0], parts[1]

		// Check for updates
		updateArgs := []string{
			"list",
			"-m",
			"-f",
			"{{if .Update}}{{.Update.Version}}{{end}}",
			"-u",
			toolPath,
		}
		updateCmd := exec.Command("go", updateArgs...)
		updateCmd.Env = append(os.Environ(), "GOWORK=off")
		if updateOutput, err := updateCmd.Output(); err == nil {
			newVersion := strings.TrimSpace(string(updateOutput))
			if newVersion != "" && newVersion != currentVersion {
				fromVersion, err := semver.NewVersion(currentVersion)
				if err != nil {
					return nil, fmt.Errorf("invalid tool version: %s -> %s: %w", toolPath, currentVersion, err)
				}
				toVersion, err := semver.NewVersion(newVersion)
				if err != nil {
					return nil, fmt.Errorf("invalid tool update version: %s -> %s: %w", toolPath, newVersion, err)
				}
				log.WithFields(log.Fields{
					"tool": toolPath,
					"from": currentVersion,
					"to":   newVersion,
				}).Debug("Found tool module update available")
				if shouldIgnore(toolPath, currentVersion, newVersion, ignoreNames) {
					continue
				}
				modules = append(modules, module.Module{
					Name: toolPath,
					From: fromVersion,
					To:   toVersion,
				})
			}
		}
	}

	return modules, nil
}

func listDirectDependencies() (map[string]string, error) {
	args := []string{
		"list",
		"-m",
		"-f",
		"{{if not (or .Main .Indirect)}}{{.Path}} {{.Version}}{{end}}",
		"all",
	}
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	deps := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			deps[parts[0]] = parts[1]
		}
	}
	return deps, nil
}

func fetchMajorUpgrades(directDeps map[string]string) ([]module.Module, []func()) {
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		results   []module.Module
		logs      []func()
		sem       = make(chan struct{}, 3) // limit concurrent pkg.go.dev requests
		apiClient = api.NewClient()
	)

	addLog := func(fn func()) {
		mu.Lock()
		logs = append(logs, fn)
		mu.Unlock()
	}

	for path, ver := range directDeps {
		wg.Add(1)
		go func(p, v string) {
			defer wg.Done()
			time.Sleep(time.Duration(rand.IntN(100)) * time.Millisecond)
			sem <- struct{}{}
			defer func() { <-sem }()

			items, err := apiClient.FetchModuleVersions(context.Background(), p)
			if err != nil {
				capturedErr := err
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "error": capturedErr}).Debug("failed to fetch major version candidates")
				})
				return
			}
			itemCount := len(items)
			addLog(func() {
				log.WithFields(log.Fields{"module": p, "count": itemCount}).Debug("fetched major version candidates")
			})

			upgrades, err := module.FindMajorUpgrades(p, v, items)
			if err != nil {
				capturedErr := err
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "error": capturedErr}).Debug("failed to find major upgrades")
				})
				return
			}
			if len(upgrades) > 0 {
				upgradeCount := len(upgrades)
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "upgrades": upgradeCount}).Debug("found major version upgrades")
				})
				mu.Lock()
				for _, up := range upgrades {
					up.IsMajorUpgrade = true
					up.OldName = p
					results = append(results, up)
				}
				mu.Unlock()
			}
		}(path, ver)
	}

	wg.Wait()
	return results, logs
}

func toolsSupported() (bool, error) {
	gv, err := exec.Command("go", "version").Output()
	if err != nil {
		return false, err
	}

	version := strings.TrimSpace(string(gv))
	re := regexp.MustCompile(`go version go([\d\.]+)(rc.+)?`)
	matched := re.FindStringSubmatch(version)
	if len(matched) < 2 {
		return false, fmt.Errorf("couldn't parse go version %s", version)
	}

	goversion, err := semver.NewVersion(matched[1])
	if err != nil {
		return false, err
	}
	log.WithFields(log.Fields{
		"major": goversion.Major(),
		"minor": goversion.Minor(),
	}).Debug("Go version")
	if goversion.Major() >= 1 && goversion.Minor() >= 24 {
		return true, nil
	}
	return false, nil
}

func shouldIgnore(name, from, to string, ignoreNames []string) bool {
	for _, ig := range ignoreNames {
		matched, _ := regexp.MatchString(ig, name)
		if matched {
			c := color.New(color.FgYellow).SprintFunc()
			log.WithFields(log.Fields{
				"name": name,
				"from": from,
				"to":   to,
			}).Debug(c("Ignore module"))
			return true
		}
	}
	return false
}

func listModules(modules []module.Module) {
	maxName := 0
	maxFrom := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.Name))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
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

func choose(modules []module.Module, pageSize int) ([]module.Module, error) {
	maxName := 0
	maxFrom := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.Name))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
	options := []string{}
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		option := fmt.Sprintf("%s %s -> %s", x.FormatName(maxName), from, x.FormatTo())
		options = append(options, option)
	}
	prompt := &MultiSelect{
		survey.MultiSelect{
			Message:  "Choose which modules to update",
			Options:  options,
			PageSize: pageSize,
		},
	}
	choice := []int{}
	err := survey.AskOne(prompt, &choice)
	if err == term.InterruptErr {
		log.Info("Bye")
		os.Exit(0)
	} else if err != nil {
		return nil, err
	}
	updates := []module.Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates, nil
}

func update(modules []module.Module, hook string) error {
	for _, x := range modules {
		if _, err := fmt.Fprintf(color.Output, "Updating %s to version %s...\n", x.FormatName(len(x.Name)), x.FormatTo()); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while updating module")
		}

		if x.IsMajorUpgrade {
			if err := module.RewriteImportsInProject(".", x.OldName, x.Name); err != nil {
				return fmt.Errorf("rewriting imports from %s to %s: %w", x.OldName, x.Name, err)
			}
		}

		if out, err := exec.Command("go", "get", x.Name).CombinedOutput(); err != nil {
			return fmt.Errorf("go get %s: %w: %s", x.Name, err, strings.TrimSpace(string(out)))
		}

		if x.IsMajorUpgrade {
			if out, err := exec.Command("go", "get", x.OldName+"@none").CombinedOutput(); err != nil {
				return fmt.Errorf("go get %s@none: %w: %s", x.OldName, err, strings.TrimSpace(string(out)))
			}
			if out, err := exec.Command("go", "mod", "tidy").CombinedOutput(); err != nil {
				return fmt.Errorf("go mod tidy: %w: %s", err, strings.TrimSpace(string(out)))
			}
			fmt.Printf("✅ Automatically upgraded imports and dependencies from '%s' to '%s'.\n", x.OldName, x.Name)
		}

		if hook != "" {
			out, err := exec.Command(
				hook,
				x.Name,
				x.From.String(),
				x.To.String(),
			).CombinedOutput()
			if err != nil {
				return fmt.Errorf("hook %s: %w: %s", hook, err, strings.TrimSpace(string(out)))
			}
			log.Info(string(out))
		}
	}
	return nil
}
