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

// rejectArgs refuses the positional arguments a caller passed, since the command takes
// none. Only the first is named, since the fix is the same either way.
//
// Ignoring them was worse than refusing: "go-mod-upgrade example.com/m" reads as a request
// to upgrade one module and upgraded every one.
//
// Checked here rather than configured, since the library has no setting for it.
// cli.Arguments declares positional arguments rather than forbidding them, and one
// declared with Max: 0 reports its own misconfiguration instead of the caller's mistake.
func rejectArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument %q", args[0])
}

func main() {
	var (
		appEnv = &app.AppEnv{}
		// The flags whose unset state means something other than false, written here
		// and promoted to the pointers on AppEnv once parsing says whether the caller
		// named them. A flag carries its default in Value, so the value alone cannot
		// distinguish a caller who asked for exactly that from one who said nothing.
		list    bool
		headers bool
		cache   bool
	)

	// A spinner leaves the cursor part-way along a line, so an entry written while
	// one draws would join it on that row. The wrapper clears the line first.
	log.SetHandler(app.LogHandler(logcli.Default))
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
			&cli.BoolWithInverseFlag{
				Name:        "non-interactive",
				Aliases:     []string{"n"},
				Value:       false,
				Usage:       "Apply every available upgrade without prompting",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_NON_INTERACTIVE"),
				Destination: &appEnv.NonInteractive,
			},
			&cli.BoolWithInverseFlag{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "List available module upgrades instead of applying them (default: unless writing to a terminal)",
				// The unset state is not false, so the value the library would
				// print is not the default. The usage names it instead.
				HideDefault: true,
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_LIST"),
				Destination: &list,
			},
			&cli.BoolWithInverseFlag{
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
			&cli.StringFlag{
				Name:  "cooldown",
				Value: app.DefaultCooldown,
				Usage: "How long a release must have been out before it is recommended, " +
					"as 7d, 2w, 3mo or 36h; a bare number means days, and 0 disables it",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_COOLDOWN"),
				Destination: &appEnv.Cooldown,
			},
			&cli.StringFlag{
				Name:  "churn",
				Value: app.DefaultChurn,
				Usage: "How far back to look for repeated releases; a module still " +
					"releasing within this window steps back to its newest settled " +
					"version rather than waiting",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_CHURN"),
				Destination: &appEnv.Churn,
			},
			&cli.StringFlag{
				Name:        "sort",
				DefaultText: strings.Join(module.DefaultSorts(), ","),
				Usage: "Sort by a comma-separated chain of " + strings.Join(module.SortKeys(), ", ") +
					", each optionally signed to reverse it or prefixed with ! to drop it from the default",
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
				Name:        "labels",
				DefaultText: strings.Join(module.DefaultFilters(), ","),
				Usage:       "List only the modules carrying a comma-separated chain of " + module.LabelLegend() + ", each optionally signed; the letter in brackets is how the label column marks the row",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_LABELS"),
				Destination: &appEnv.Labels,
			},
			&cli.StringFlag{
				Name:        "format",
				Value:       module.DefaultFormat,
				Usage:       "Write the listing as " + strings.Join(module.FormatNames(), ", "),
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_FORMAT"),
				Destination: &appEnv.Format,
			},
			&cli.StringFlag{
				Name:    "columns",
				Aliases: []string{"k"},
				Usage: "Show these columns, a comma-separated chain of " +
					strings.Join(module.ColumnNames(), ", ") +
					", each optionally signed to adjust the default rather than replace it",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_COLUMNS"),
				Destination: &appEnv.Columns,
			},
			&cli.BoolWithInverseFlag{
				Name:        "headers",
				Aliases:     []string{"H"},
				Usage:       "Precede the listing with column headings (default: when writing to a terminal)",
				HideDefault: true,
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_HEADERS"),
				Destination: &headers,
			},
			&cli.StringSliceFlag{
				Name: "tags",
				Usage: "Build configurations to analyse, as build constraints; " +
					"signed to adjust what the project declares rather than replace it",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_TAGS"),
				Destination: &appEnv.Tags,
			},
			&cli.IntFlag{
				Name:        "width",
				Aliases:     []string{"w"},
				Usage:       "Columns a listing may use, 0 for the terminal's own width and -1 for unlimited",
				DefaultText: "the terminal's width",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_WIDTH"),
				Destination: &appEnv.Width,
			},
			&cli.StringFlag{
				Name:  "cache-for",
				Value: app.DefaultUpdateWindow,
				Usage: "How long to reuse an answer about available upgrades, as 1d, 2d or 12h; " +
					"0 asks the proxy every run",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_CACHE_FOR"),
				Destination: &appEnv.CacheFor,
			},
			&cli.BoolWithInverseFlag{
				Name:  "cache",
				Value: true,
				Usage: "Reuse a vulnerability scan while nothing that decides it has changed " +
					"(default: unless --timing, which measures the work rather than the cache)",
				HideDefault: true,
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_CACHE_SCANS"),
				Destination: &cache,
			},
			&cli.BoolWithInverseFlag{
				Name:        "timing",
				Value:       false,
				Usage:       "Report what each phase of the run cost, slowest first",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_TIMING"),
				Destination: &appEnv.Timing,
			},
			&cli.BoolWithInverseFlag{
				Name:        "color",
				Value:       true,
				Usage:       "Colour the output",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_COLOR"),
				Destination: &appEnv.Color,
			},
			&cli.StringFlag{
				Name:        "colors",
				Usage:       "Override colours as role=attributes pairs, as in " + strconv.Quote("vuln=bold+red,from=faint"),
				Sources:     cli.EnvVars(module.ColorsEnv),
				Destination: &appEnv.Colors,
			},
			&cli.BoolWithInverseFlag{
				Name:        "work-sync",
				Value:       false,
				Usage:       "Run go work sync after updating, in workspace mode",
				Sources:     cli.EnvVars("GO_MOD_UPGRADE_WORK_SYNC"),
				Destination: &appEnv.WorkSync,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if err := rejectArgs(cmd.Args().Slice()); err != nil {
				return err
			}
			// The three flags whose unset state is not false. A flag carries its
			// default in Value, so the value cannot say whether anyone chose it --
			// and each of these means something else when nobody did: a listing
			// when the output is redirected, a heading at a terminal, the cache
			// unless timing. Naming the flag either way settles it, which is what
			// the pointer records.
			//
			// The library tracks which of the three states an inverse flag is in
			// but exposes only the value, so the state is rebuilt here from IsSet.
			if cmd.IsSet("list") {
				appEnv.List = &list
			}
			if cmd.IsSet("headers") {
				appEnv.Headers = &headers
			}
			if cmd.IsSet("cache") {
				appEnv.Cache = &cache
			}
			// Both periods carry their default in the flag, so the value cannot say
			// whether anyone chose it -- and that is what decides whether a policy
			// setting the same period is overridden or obeyed.
			appEnv.CooldownSet = cmd.IsSet("cooldown")
			appEnv.ChurnSet = cmd.IsSet("churn")
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
		os.Exit(appEnv.ExitStatus(err))
	}
}
