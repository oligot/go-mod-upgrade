package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
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

func discover() ([]Module, error) {
	fmt.Println("Discovering modules...")
	goversion := strings.TrimPrefix(runtime.Version(), "go")
	version, err := semver.NewVersion(string(goversion))
	if err != nil {
		return nil, err
	}
	args := []string{"list", "-u"}
	if version.Major() == 1 && version.Minor() >= 14 {
		args = append(args, "-mod=mod")
	}
	args = append(args, []string{"-f", "'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}'", "-m", "all"}...)
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
			from, _ := semver.NewVersion(matched[2])
			to, _ := semver.NewVersion(matched[3])
			d := Module{
				name: matched[1],
				from: from,
				to:   to,
			}
			modules = append(modules, d)
		}
	}
	return modules, nil
}

func choose(modules []Module) []Module {
	maxName := 0
	maxFrom := 0
	maxTo := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.name))
		maxFrom = max(maxFrom, len(x.from.String()))
		maxTo = max(maxTo, len(x.to.String()))
	}
	fd := int(os.Stdout.Fd())
	termWidth, _, err := terminal.GetSize(fd)
	if err != nil {
		fmt.Printf("Error while getting terminal size %v\n", err)
	}
	options := []string{}
	for _, x := range modules {
		from := ""
		// Only show from when the terminal width is big enough
		// As there is a bug in survey when the terminal overflows
		// https://github.com/AlecAivazis/survey/issues/101
		if termWidth > maxName+maxFrom+maxTo+11 {
			from = formatFrom(x.from, maxFrom)
		}
		options = append(options, fmt.Sprintf("%s %s -> %s", formatName(x, maxName), from, formatTo(x)))
	}
	prompt := &survey.MultiSelect{
		Message:  "Choose which modules to update",
		Options:  options,
		PageSize: 10,
	}
	choice := []int{}
	err = survey.AskOne(prompt, &choice)
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

func update(modules []Module) {
	for _, x := range modules {
		fmt.Fprintf(color.Output, "Updating %s to version %s...\n", formatName(x, len(x.name)), formatTo(x))
		out, err := exec.Command("go", "get", x.name).CombinedOutput()
		if err != nil {
			fmt.Printf("Error while updating %s: %s\n", x.name, string(out))
		}
	}
}

func main() {
	modules, err := discover()
	if err != nil {
		log.Fatal(err)
	}
	if len(modules) > 0 {
		modules = choose(modules)
		update(modules)
	} else {
		fmt.Println("All modules are up to date")
	}
}
