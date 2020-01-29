package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
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
			same = false
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

func discover() []Module {
	fmt.Println("Discovering modules...")
	list, err := exec.Command("go", "list", "-u", "-f", "'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}'", "-m", "all").Output()
	if err != nil {
		log.Fatal(err)
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
	return modules
}

func choose(modules []Module) []Module {
	choice := []int{}
	options := []string{}
	maxName := 0
	maxVersion := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.name))
		maxVersion = max(maxVersion, len(x.from.String()))
	}
	for _, x := range modules {
		options = append(options, fmt.Sprintf("%s %s -> %s", formatName(x, maxName), formatFrom(x.from, maxVersion), formatTo(x)))
	}
	prompt := &survey.MultiSelect{
		Message:  "Choose which modules to update",
		Options:  options,
		PageSize: 10,
	}
	survey.AskOne(prompt, &choice)
	updates := []Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(modules []Module) {
	for _, x := range modules {
		fmt.Fprintf(color.Output, "Updating %s to version %s...\n", formatName(x, len(x.name)), formatTo(x))
		err := exec.Command("go", "get", x.name).Run()
		if err != nil {
			fmt.Printf("Error while updating %s: %v\n", x.name, err)
		}
	}
}

func main() {
	modules := discover()
	if len(modules) > 0 {
		modules = choose(modules)
		update(modules)
	} else {
		fmt.Println("All modules are up to date")
	}
}
