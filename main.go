package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

var (
	// Variables populated during the compilation phase
	version = "(undefined)"
	commit  = "(undefined)"
	date    = "(undefined)"
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

func commitUpdate(module Module) ([]byte, error) {
	commitMsg := fmt.Sprintf("chore(deps): bump %s from %s to %s", module.name, module.from, module.to)

	const commitMsgMaxLen = 72
	if len(commitMsg) > commitMsgMaxLen {
		commitMsg = commitMsg[:commitMsgMaxLen] + "\n\n" + commitMsg[commitMsgMaxLen:]
	}

	out, err := exec.Command("git", "add", "go.mod", "go.sum").CombinedOutput()
	if err != nil {
		return out, err
	}

	out, err = exec.Command("git", "commit", "-m", commitMsg).CombinedOutput()
	if err != nil {
		return out, err
	}

	return nil, nil
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

func discover(verbose bool) ([]Module, error) {
	fmt.Println("Discovering modules...")
	args := []string{
		"list",
		"-u",
		"-mod=mod",
		"-f",
		"'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}'",
		"-m",
		"all",
	}
	list, err := exec.Command("go", args...).Output()
	if err != nil {
		return nil, err
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
			if verbose {
				fmt.Printf("Found module %s, from %s to %s\n", name, from, to)
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
		fmt.Println("Bye")
		os.Exit(0)
	} else if err != nil {
		log.Fatal(err)
	}
	updates := []Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(modules []Module, commit bool) {
	for _, x := range modules {
		fmt.Fprintf(color.Output, "Updating %s to version %s...\n", formatName(x, len(x.name)), formatTo(x))
		out, err := exec.Command("go", "get", x.name).CombinedOutput()
		if err != nil {
			fmt.Printf("Error while updating %s: %s\n", x.name, string(out))
		}

		if commit {
			if out, err := commitUpdate(x); err != nil {
				log.Fatalf("Error while comitting update of %s: %s\n", x.name, string(out))
			}
		}
	}
}

func main() {
	var (
		force     bool
		gitCommit bool
		pageSize  int
		verbose   bool
	)

	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version",
		Usage: "print the version",
	}
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf(
			"%v version=%v commit=%v date=%v\n",
			c.App.Name,
			c.App.Version,
			commit,
			date,
		)
	}

	app := &cli.App{
		Name:    "go-mod-upgrade",
		Usage:   "Update outdated Go dependencies interactively",
		Version: version,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "commit",
				Aliases:     []string{"c"},
				Value:       false,
				Usage:       "Git commit each update",
				Destination: &gitCommit,
			},
			&cli.BoolFlag{
				Name:        "force",
				Aliases:     []string{"f"},
				Value:       false,
				Usage:       "Force update all modules in non-interactive mode",
				Destination: &force,
			},
			&cli.IntFlag{
				Name:        "pagesize",
				Aliases:     []string{"p"},
				Value:       10,
				Usage:       "Specify page size",
				Destination: &pageSize,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Aliases:     []string{"v"},
				Value:       false,
				Usage:       "Verbose mode",
				Destination: &verbose,
			},
		},
		Action: func(c *cli.Context) error {
			modules, err := discover(verbose)
			if err != nil {
				log.Fatal(err)
			}
			if force {
				if verbose {
					fmt.Println("Update all modules in non-interactive mode...")
				}
				update(modules, gitCommit)
				return nil
			}
			if len(modules) > 0 {
				modules = choose(modules, pageSize)
				update(modules, gitCommit)
			} else {
				fmt.Println("All modules are up to date")
			}
			return nil
		},
		UseShortOptionHandling: true,
		EnableBashCompletion:   true,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
