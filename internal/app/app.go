package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/fatih/color"
	"golang.org/x/mod/modfile"

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
	Indirect bool
	Sort     string
}

func (app *AppEnv) Run(ctx context.Context) error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	sortBy := app.Sort
	if sortBy == "" {
		sortBy = module.DefaultSort
	}
	// Resolve the comparator up front so an unusable value fails before any
	// network work has been done.
	sorter, err := module.Lookup(sortBy)
	if err != nil {
		return err
	}
	var paths []string
	gw, err := exec.CommandContext(ctx, "go", "env", "GOWORK").Output()
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
		// Read the work file through a root confined to its own directory, so
		// a symlink in the path cannot lead the read elsewhere.
		root, err := os.OpenRoot(filepath.Dir(gowork))
		if err != nil {
			return err
		}
		content, err := root.ReadFile(filepath.Base(gowork))
		if closeErr := root.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
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
		dir := path
		if !filepath.IsAbs(path) {
			dir = filepath.Join(filepath.Dir(gowork), path)
		}
		log.WithField("dir", dir).Info("Using directory")
		modules, err := discoverModules(ctx, dir, app.Ignore, app.Indirect)
		if err != nil {
			return err
		}
		supported, err := toolsSupported(ctx)
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"supported": supported,
		}).Debug("Tool support")
		if supported {
			toolModules, err := discoverTools(ctx, dir, app.Ignore)
			if err != nil {
				return err
			}
			modules = append(modules, toolModules...)
		}
		// Sort once the tool modules have been merged in, so the whole list
		// shares one order rather than tools trailing behind.
		slices.SortStableFunc(modules, sorter)
		if len(modules) > 0 {
			if app.List {
				listModules(modules)
			} else if app.Force {
				log.Debug("Update all modules in non-interactive mode...")
				update(ctx, dir, modules, app.Hook)
			} else {
				modules = choose(modules, app.PageSize)
				update(ctx, dir, modules, app.Hook)
			}
		} else {
			fmt.Println("All modules are up to date")
		}
	}
	return nil
}

func discoverTools(ctx context.Context, dir string, ignoreNames []string) ([]module.Module, error) {
	stop, err := progress("Discovering tool modules...")
	if err != nil {
		return nil, err
	}
	defer stop()

	toolsArgs := []string{
		"list",
		"-f",
		"{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}",
		"tool",
	}
	cmd := exec.CommandContext(ctx, "go", toolsArgs...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	toolsOutput, err := cmd.Output()

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

		// Check for updates. Query as path@version so the lookup does not
		// depend on the main module's build list or go.sum.
		updateArgs := []string{
			"list",
			"-m",
			"-f",
			"{{if .Update}}{{.Update.Version}}{{end}}",
			"-u",
			"-e",
			toolPath + "@" + currentVersion,
		}
		updateCmd := exec.CommandContext(ctx, "go", updateArgs...)
		updateCmd.Dir = dir
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

	// Clear the spinner before the caller starts printing, so its trailing
	// blanks do not end up on the first line of the listing.
	stop()
	return modules, nil
}

func toolsSupported(ctx context.Context) (bool, error) {
	gv, err := exec.CommandContext(ctx, "go", "version").Output()
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
		if strings.Contains(name, ig) {
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

// columnWidths returns the widths needed to align the name and current
// version columns. Names are measured with DisplayName, since FormatName
// writes colour escapes that would otherwise be counted as visible.
func columnWidths(modules []module.Module) (maxName, maxFrom int) {
	for _, x := range modules {
		maxName = max(maxName, len(x.DisplayName()))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
	return maxName, maxFrom
}

func listModules(modules []module.Module) {
	maxName, maxFrom := columnWidths(modules)
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

func choose(modules []module.Module, pageSize int) []module.Module {
	maxName, maxFrom := columnWidths(modules)
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
		log.WithError(err).Error("Choose failed")
		os.Exit(1)
	}
	updates := []module.Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(ctx context.Context, dir string, modules []module.Module, hook string) {
	for _, x := range modules {
		_, err := fmt.Fprintf(color.Output, "Updating %s to version %s...\n", x.FormatName(len(x.DisplayName())), x.FormatTo())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while updating module")
		}
		// Ask for the version that was reported, rather than letting go get
		// resolve @latest, which may have moved on since discovery. Original
		// keeps the leading "v", which String strips and pseudo-versions need.
		cmd := exec.CommandContext(ctx, "go", "get", x.Name+"@"+x.To.Original())
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
				"out":   string(out),
			}).Error("Error while updating module")
		}
		if hook != "" {
			cmd := exec.CommandContext(
				ctx,
				hook,
				x.Name,
				x.From.String(),
				x.To.String(),
			)
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"hook":  hook,
					"out":   string(out),
				}).Error("Error while executing hook")
				os.Exit(1)
			}
			log.Info(string(out))
		}
	}
}
