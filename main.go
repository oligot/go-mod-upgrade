package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"golang.org/x/mod/modfile"
)

var (
	// Variables populated during the compilation phase
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

func padRight(str string, length int) string {
	if len(str) >= length {
		return str
	}
	return str + strings.Repeat(" ", length-len(str))
}

func formatName(module Module, length int) string {
	c := color.New(color.FgWhite).SprintFunc()
	from := module.from
	to := module.to
	if from.Minor() != to.Minor() {
		c = color.New(color.FgYellow).SprintFunc()
	}
	if from.Patch() != to.Patch() {
		c = color.New(color.FgGreen).SprintFunc()
	}
	if from.Prerelease() != to.Prerelease() {
		c = color.New(color.FgRed).SprintFunc()
	}
	return c(padRight(module.name, length))
}

func formatFrom(from *semver.Version, length int) string {
	c := color.New(color.FgBlue).SprintFunc()
	return c(padRight(from.String(), length))
}

func formatTo(module Module) string {
	green := color.New(color.FgGreen).SprintFunc()
	var buf bytes.Buffer
	from := module.from
	to := module.to
	same := true
	fmt.Fprintf(&buf, "%d.", to.Major())
	if from.Minor() == to.Minor() {
		fmt.Fprintf(&buf, "%d.", to.Minor())
	} else {
		fmt.Fprintf(&buf, "%s%s", green(to.Minor()), green("."))
		same = false
	}
	if from.Patch() == to.Patch() && same {
		fmt.Fprintf(&buf, "%d", to.Patch())
	} else {
		fmt.Fprintf(&buf, "%s", green(to.Patch()))
		same = false
	}
	if to.Prerelease() != "" {
		if from.Prerelease() == to.Prerelease() && same {
			fmt.Fprintf(&buf, "-%s", to.Prerelease())
		} else {
			fmt.Fprintf(&buf, "-%s", green(to.Prerelease()))
		}
	}
	if to.Metadata() != "" {
		fmt.Fprintf(&buf, "%s%s", green("+"), green(to.Metadata()))
	}
	return buf.String()
}

type Module struct {
	name string
	from *semver.Version
	to   *semver.Version
}

// MultiSelect that doesn't show the answer
// It just reset the prompt and the answers are shown afterwards
type MultiSelect struct {
	survey.MultiSelect
}

func (m MultiSelect) Cleanup(config *survey.PromptConfig, val interface{}) error {
	return m.Render("", nil)
}

type appEnv struct {
	verbose  bool
	force    bool
	pageSize int
	hook     string
	ignore   cli.StringSlice
}

func (app *appEnv) run() error {
	if app.verbose {
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
		modules, err := discover(app.ignore.Value())
		if err != nil {
			return err
		}
		if len(modules) > 0 {
			if app.force {
				log.Debug("Update all modules in non-interactive mode...")
			} else {
				modules = choose(modules, app.pageSize)
			}
			update(modules, app.hook)
		} else {
			fmt.Println("All modules are up to date")
		}
		if err := os.Chdir(cwd); err != nil {
			return err
		}
	}
	return nil
}

func discover(ignoreNames []string) ([]Module, error) {
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
	cmd.Env = os.Environ()
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(cmd.Env, "GOWORK=off")
	list, err := cmd.Output()
	s.Stop()

	// Clear line
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))

	if err != nil {
		return nil, fmt.Errorf("Error running go command to discover modules: %w", err)
	}

	split := strings.Split(string(list), "\n")
	modules := []Module{}
	re := regexp.MustCompile(`'(.+): (.+) -> (.+)'`)
	for _, x := range split {
		if x != "''" && x != "" {
			matched := re.FindStringSubmatch(x)
			if len(matched) < 4 {
				return nil, fmt.Errorf("Couldn't parse module %s", x)
			}
			name, from, to := matched[1], matched[2], matched[3]
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
			d := Module{
				name: name,
				from: fromversion,
				to:   toversion,
			}
			modules = append(modules, d)
		}
	}
	return modules, nil
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

func choose(modules []Module, pageSize int) []Module {
	maxName := 0
	maxFrom := 0
	maxTo := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.name))
		maxFrom = max(maxFrom, len(x.from.String()))
		maxTo = max(maxTo, len(x.to.String()))
	}
	options := []string{}
	for _, x := range modules {
		from := formatFrom(x.from, maxFrom)
		option := fmt.Sprintf("%s %s -> %s", formatName(x, maxName), from, formatTo(x))
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
	updates := []Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(modules []Module, hook string) {
	for _, x := range modules {
		fmt.Fprintf(color.Output, "Updating %s to version %s...\n", formatName(x, len(x.name)), formatTo(x))
		out, err := exec.Command("go", "get", "-d", x.name).CombinedOutput()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.name,
				"out":   string(out),
			}).Error("Error while updating module")
		}
		if hook != "" {
			out, err := exec.Command(hook, x.name, x.from.String(), x.to.String()).CombinedOutput()
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

func versionPrinter(c *cli.Context) {
	version := c.App.Version
	if commit != "" {
		version = fmt.Sprintf("%s\ncommit: %s", version, commit)
	}
	if date != "" {
		version = fmt.Sprintf("%s\nbuild at: %s", version, date)
	}
	if builtBy != "" {
		version = fmt.Sprintf("%s\nbuilt by: %s", version, builtBy)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		version = fmt.Sprintf("%s\nmodule version: %s", version, info.Main.Version)
	}
	fmt.Printf(
		"%s version %s\n",
		c.App.Name,
		version,
	)
}

func main() {
	var (
		app = &appEnv{}
	)

	log.SetHandler(logcli.Default)

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version",
		Usage: "print the version",
	}
	cli.VersionPrinter = versionPrinter

	cliapp := &cli.App{
		Name:    "go-mod-upgrade",
		Usage:   "Update outdated Go dependencies interactively",
		Version: version,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "pagesize",
				Aliases:     []string{"p"},
				Value:       10,
				Usage:       "Specify page size",
				Destination: &app.pageSize,
			},
			&cli.BoolFlag{
				Name:        "force",
				Aliases:     []string{"f"},
				Value:       false,
				Usage:       "Force update all modules in non-interactive mode",
				Destination: &app.force,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Verbose mode",
				Destination: &app.verbose,
			},
			&cli.PathFlag{
				Name:        "hook",
				Usage:       "Hook to execute for each updated module",
				Destination: &app.hook,
			},
			&cli.StringSliceFlag{
				Name:        "ignore",
				Aliases:     []string{"i"},
				Usage:       "Ignore modules matching the given regular expression",
				Destination: &app.ignore,
			},
		},
		Action: func(c *cli.Context) error {
			return app.run()
		},
		UseShortOptionHandling: true,
		EnableBashCompletion:   true,
	}

	err := cliapp.Run(os.Args)
	if err != nil {
		logger := log.WithError(err)
		var e *exec.ExitError
		if errors.As(err, &e) {
			logger = logger.WithField("stderr", string(e.Stderr))
		}
		logger.Error("upgrade failed")
		os.Exit(1)
	}
}
