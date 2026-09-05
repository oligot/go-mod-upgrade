package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/urfave/cli/v3"

	"github.com/oligot/go-mod-upgrade/internal/app"
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
		app = &app.AppEnv{}
	)

	log.SetHandler(logcli.Default)

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
			&cli.IntFlag{
				Name:        "pagesize",
				Aliases:     []string{"p"},
				Value:       10,
				Usage:       "Specify page size",
				Destination: &app.PageSize,
			},
			&cli.BoolFlag{
				Name:        "force",
				Aliases:     []string{"f"},
				Value:       false,
				Usage:       "Force update all modules in non-interactive mode",
				Destination: &app.Force,
			},
			&cli.BoolFlag{
				Name:        "list",
				Aliases:     []string{"l"},
				Value:       false,
				Usage:       "List available module upgrades without interactivity",
				Destination: &app.List,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Verbose mode",
				Destination: &app.Verbose,
			},
			&cli.StringFlag{
				Name:        "hook",
				Usage:       "Hook to execute for each updated module",
				TakesFile:   true,
				Destination: &app.Hook,
			},
			&cli.StringSliceFlag{
				Name:        "ignore",
				Aliases:     []string{"i"},
				Usage:       "Ignore modules matching the given regular expression",
				Destination: &app.Ignore,
			},
			&cli.BoolFlag{
				Name:        "no-major",
				Value:       false,
				Usage:       "Disable checking for major version updates",
				Destination: &app.NoMajor,
			},
			&cli.BoolFlag{
				Name:        "no-cache",
				Value:       false,
				Usage:       "Skip the disk cache when checking for major version updates",
				Destination: &app.NoCache,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return app.Run()
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
		os.Exit(1)
	}
}
