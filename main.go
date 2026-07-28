package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/fatih/color"
	"github.com/urfave/cli/v3"

	"github.com/oligot/go-mod-upgrade/internal/app"
	"github.com/oligot/go-mod-upgrade/internal/module"
)

var (
	// Variables populated during the compilation phase
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func versionPrinter(cmd *cli.Command) {
	version := cmd.Version
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
		cmd.Name,
		version,
	)
}

func main() {
	var (
		appEnv = &app.AppEnv{}
	)

	log.SetHandler(logcli.Default)
	// The handler paints informational lines blue, which is hard to read
	// against either background. They are context rather than news, so they
	// recede instead; warnings and errors keep their own colours.
	logcli.Colors[log.InfoLevel] = color.New(color.Faint)

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version",
		Usage: "print the version",
	}
	cli.VersionPrinter = versionPrinter

	cliapp := &cli.Command{
		Name:    "go-mod-upgrade",
		Usage:   "Update outdated Go dependencies interactively",
		Version: version,
		Flags: []cli.Flag{
			&cli.FloatFlag{
				Name:        "pagesize",
				Aliases:     []string{"p"},
				Value:       app.DefaultPageSize,
				Usage:       "Number of modules to display (% of terminal when <=1.0, or absolute number of rows)",
				Destination: &appEnv.PageSize,
			},
			&cli.BoolFlag{
				Name:        "force",
				Aliases:     []string{"f"},
				Value:       false,
				Usage:       "Force update all modules in non-interactive mode",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_FORCE"),
				Destination: &appEnv.Force,
			},
			&cli.BoolFlag{
				Name:        "list",
				Aliases:     []string{"l"},
				Value:       false,
				Usage:       "List available module upgrades without interactivity",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_LIST"),
				Destination: &appEnv.List,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Verbose mode",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_VERBOSE"),
				Destination: &appEnv.Verbose,
			},
			&cli.StringFlag{
				Name:        "hook",
				Usage:       "Hook to execute for each updated module",
				TakesFile:   true,
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_HOOK"),
				Destination: &appEnv.Hook,
			},
			&cli.StringSliceFlag{
				Name:        "ignore",
				Aliases:     []string{"i"},
				Usage:       "Ignore modules matching the given regular expression",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_IGNORE"),
				Destination: &appEnv.Ignore,
			},
			&cli.BoolFlag{
				Name:        "indirect",
				Value:       false,
				Usage:       "Also show indirect dependencies declared in go.mod",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_INDIRECT"),
				Destination: &appEnv.Indirect,
			},
			&cli.BoolFlag{
				Name:        "all",
				Value:       false,
				Usage:       "Show every module in the build list, not only those recorded in go.mod",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_ALL"),
				Destination: &appEnv.All,
			},
			&cli.BoolFlag{
				Name:        "vuln",
				Value:       false,
				Usage:       "Report known vulnerabilities affecting each module",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_VULN"),
				Destination: &appEnv.Vuln,
			},
			&cli.StringFlag{
				Name:        "sort",
				Value:       module.DefaultSort,
				Usage:       "Sort by a comma-separated chain of " + strings.Join(module.SortKeys(), ", ") + ", each optionally signed",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_SORT"),
				Destination: &appEnv.Sort,
			},
			&cli.StringSliceFlag{
				Name:        "policy",
				Usage:       "Check the modules against policy files, merged in order",
				TakesFile:   true,
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_POLICY"),
				Destination: &appEnv.Policy,
			},
			&cli.StringFlag{
				Name:        "show",
				Value:       module.DefaultShow,
				Usage:       "Show modules matching a comma-separated chain of " + strings.Join(module.ShowKeys(), ", ") + ", each optionally signed",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_SHOW"),
				Destination: &appEnv.Show,
			},
			&cli.StringFlag{
				Name:        "format",
				Value:       module.DefaultFormat,
				Usage:       "Write the listing as " + strings.Join(module.FormatNames(), ", "),
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_FORMAT"),
				Destination: &appEnv.Format,
			},
			&cli.BoolFlag{
				Name:        "no-color",
				Value:       false,
				Usage:       "Disable colour in the output",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_NO_COLOR"),
				Destination: &appEnv.NoColor,
			},
			&cli.StringFlag{
				Name:        "colors",
				Usage:       "Override colours as role=attributes pairs, as in " + strconv.Quote("cve=bold+red,from=faint"),
				Sources:     cli.EnvVars(module.ColorsEnv),
				Destination: &appEnv.Colors,
			},
			&cli.BoolFlag{
				Name:        "work-sync",
				Value:       false,
				Usage:       "Run go work sync after updating, in workspace mode",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_WORK_SYNC"),
				Destination: &appEnv.WorkSync,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return appEnv.Run(ctx)
		},
		UseShortOptionHandling: true,
		EnableShellCompletion:  true,
	}

	err := cliapp.Run(context.Background(), os.Args)
	if err != nil {
		logger := log.WithError(err)
		var e *exec.ExitError
		if errors.As(err, &e) {
			logger = logger.WithField("stderr", string(e.Stderr))
		}
		logger.Error("upgrade failed")
		// A policy names the status it wants left behind, so that a check can
		// be told apart from the tool failing to run.
		os.Exit(app.ExitStatus(err))
	}
}
