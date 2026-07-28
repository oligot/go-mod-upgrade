package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/core"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/fatih/color"
	xterm "golang.org/x/term"

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

// selectTemplate is survey's own multi-select template with two additions: the
// position within the list beside the question, and a note below the options
// when the list is longer than the page.
//
// Without them a page that fills the window looks like the whole list, since
// survey renders no indication that anything follows.
const selectTemplate = `
{{- define "option"}}
    {{- if eq .SelectedIndex .CurrentIndex }}{{color .Config.Icons.SelectFocus.Format }}{{ .Config.Icons.SelectFocus.Text }}{{color "reset"}}{{else}} {{end}}
    {{- if index .Checked .CurrentOpt.Index }}{{color .Config.Icons.MarkedOption.Format }} {{ .Config.Icons.MarkedOption.Text }} {{else}}{{color .Config.Icons.UnmarkedOption.Format }} {{ .Config.Icons.UnmarkedOption.Text }} {{end}}
    {{- color "reset"}}
    {{- " "}}{{- .CurrentOpt.Value}}{{ if ne ($.GetDescription .CurrentOpt) "" }} - {{color "cyan"}}{{ $.GetDescription .CurrentOpt }}{{color "reset"}}{{end}}
{{end}}
{{- if .ShowHelp }}{{- color .Config.Icons.Help.Format }}{{ .Config.Icons.Help.Text }} {{ .Help }}{{color "reset"}}{{"\n"}}{{end}}
{{- color .Config.Icons.Question.Format }}{{ .Config.Icons.Question.Text }} {{color "reset"}}
{{- color "default+hb"}}{{ .Message }}{{ .FilterMessage }}{{color "reset"}}
{{- if .ShowAnswer}}{{color "cyan"}} {{.Answer}}{{color "reset"}}{{"\n"}}
{{- else }}
	{{- " "}}{{- color "cyan"}}[{{ inc .SelectedIndex }}/{{ len .Options }}]{{color "reset"}}
	{{- "  "}}{{- color "cyan"}}[Use arrows to move, space to select,{{- if not .Config.RemoveSelectAll }} <right> to all,{{end}}{{- if not .Config.RemoveSelectNone }} <left> to none,{{end}} type to filter{{- if and .Help (not .ShowHelp)}}, {{ .Config.HelpInput }} for more help{{end}}]{{color "reset"}}
  {{- "\n"}}
  {{- range $ix, $option := .PageEntries}}
    {{- template "option" $.IterateOption $ix $option}}
  {{- end}}
  {{- $hidden := sub (len .Options) (len .PageEntries)}}
  {{- if gt $hidden 0}}{{- color "faint"}}    ... {{ $hidden }} more, scroll to see{{color "reset"}}{{"\n"}}{{end}}
{{- end}}`

// init gives the prompt template the arithmetic it needs to report the position
// within a list. survey's own function map offers only colour.
func init() {
	for _, funcs := range []map[string]any{
		core.TemplateFuncsWithColor,
		core.TemplateFuncsNoColor,
	} {
		funcs["inc"] = func(i int) int { return i + 1 }
		funcs["sub"] = func(a, b int) int { return a - b }
	}
	// The template is a package-level variable in survey, so replacing it here
	// applies to every multi-select prompt.
	survey.MultiSelectQuestionTemplate = selectTemplate
}

// DefaultPageSize is the share of the terminal the selection prompt occupies
// when --pagesize is not given.
const DefaultPageSize = 0.8

type AppEnv struct {
	Verbose  bool
	Force    bool
	List     bool
	PageSize float64
	Hook     string
	Ignore   []string
	Indirect bool
	All      bool
	Vuln     bool
	Sort     string
	WorkSync bool
}

// scope reports which dependencies the flags ask for.
func (app *AppEnv) scope() scope {
	switch {
	case app.All:
		return scopeAll
	case app.Indirect:
		return scopeIndirect
	default:
		return scopeDirect
	}
}

func (app *AppEnv) Run(ctx context.Context) error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	// Resolve the chain up front so an unusable key fails before any network
	// work has been done.
	sorter, err := module.ParseSort(app.Sort)
	if err != nil {
		return err
	}
	// Dependent counts are only gathered with --all, so without it that key
	// cannot order anything. Report it rather than sorting arbitrarily.
	if !app.All && slices.Contains(sorter.Keys, module.SortDeps) {
		log.Warn("Sorting by dependents requires --all, so that key is ignored")
	}
	if app.All {
		// Upgrading a module that go.mod does not record adds a requirement
		// to it, and only go mod tidy takes those back out again.
		log.Warn("--all can add // indirect requirements to go.mod; run go mod tidy afterwards")
	}
	gw, err := exec.CommandContext(ctx, "go", "env", "GOWORK").Output()
	if err != nil {
		return err
	}
	gowork := strings.TrimSpace(string(gw))
	workspace := gowork != "" && gowork != "off"

	var dirs []string
	if workspace {
		log.WithField("gowork", gowork).Info("Workspace mode")
		dirs, err = workspaceDirs(gowork)
		if err != nil {
			return err
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		dirs = append(dirs, cwd)
	}

	// A module that cannot be read should not hide the updates available in
	// the rest of the workspace, so failures are collected and reported once
	// every module has been given a chance.
	var errs []error
	updated := 0
	if workspace && app.All {
		// The members of a workspace share most of their dependencies, so
		// offering each member separately would ask about the same upgrade
		// repeatedly. Gather them into one list instead.
		n, err := app.runWorkspace(ctx, dirs, sorter)
		if err != nil {
			errs = append(errs, err)
		}
		updated += n
	} else {
		for _, dir := range dirs {
			log.WithField("dir", dir).Info("Using directory")
			n, err := app.runDir(ctx, dir, sorter)
			if err != nil {
				log.WithFields(log.Fields{
					"dir":   dir,
					"error": err,
				}).Error("Skipping module")
				errs = append(errs, fmt.Errorf("%q: %w", dir, err))
				continue
			}
			updated += n
		}
	}

	if workspace && app.WorkSync && updated > 0 {
		if err := workSync(ctx, filepath.Dir(gowork)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// runWorkspace offers the updates available across every module of a
// workspace as one list, and reports how many modules were updated.
//
// The members of a workspace share most of their dependencies, so each upgrade
// is offered once and applied to whichever members require it. RequiredBy
// names those members, which is what makes the choice meaningful: whether a
// module is required directly is a property of each member, not of the
// workspace.
func (app *AppEnv) runWorkspace(ctx context.Context, dirs []string, sorter module.Sort) (int, error) {
	// Which members require a given module, keyed by module path.
	members := map[string][]string{}
	// One representative entry per module, holding the versions to show.
	byPath := map[string]module.Module{}
	// Advisories seen for a module, in any member that requires it.
	found := vulnerabilities{}
	var errs []error

	for _, dir := range dirs {
		log.WithField("dir", dir).Info("Using directory")
		discovered, err := discoverModules(ctx, dir, app.Ignore, app.scope())
		if err != nil {
			log.WithFields(log.Fields{
				"dir":   dir,
				"error": err,
			}).Error("Skipping module")
			errs = append(errs, fmt.Errorf("%q: %w", dir, err))
			continue
		}
		if app.Vuln {
			// Each member has to be scanned separately: govulncheck needs a
			// go.mod, and the directory holding go.work usually has none.
			vulns, err := scanVulnerabilities(ctx, dir)
			if err != nil {
				return 0, errors.Join(append(errs, err)...)
			}
			mergeVulns(found, vulns)
		}
		for _, m := range discovered {
			members[m.Name] = append(members[m.Name], dir)
			// Members can require different versions of the same module. Keep
			// the oldest, since that is the one most in need of the upgrade.
			if prev, ok := byPath[m.Name]; !ok || m.From.LessThan(prev.From) {
				byPath[m.Name] = m
			}
		}
	}

	modules := make([]module.Module, 0, len(byPath))
	for path, m := range byPath {
		// Sort only what is displayed; the members map keeps its own order so
		// that a choice can be mapped back to a directory.
		names := relativeTo(members[path], dirs)
		slices.Sort(names)
		m.RequiredBy = names
		modules = append(modules, m)
	}
	if app.Vuln {
		annotateVulns(modules, found)
	}
	slices.SortStableFunc(modules, sorter.Compare)

	if len(modules) == 0 {
		fmt.Println("All modules are up to date")
		return 0, errors.Join(errs...)
	}
	if app.List {
		listModules(modules)
		return 0, errors.Join(errs...)
	}
	if !app.Force {
		modules = choose(modules, app.PageSize)
	} else {
		log.Debug("Update all modules in non-interactive mode...")
	}

	updated := 0
	for _, m := range modules {
		dirs := members[m.Name]
		// A module required by one member has nothing to choose between, and
		// --force takes everything by definition.
		if len(dirs) > 1 && !app.Force {
			chosen, err := chooseMembers(m, dirs, relativeTo(dirs, dirs), app.PageSize)
			if err != nil {
				return updated, errors.Join(append(errs, err)...)
			}
			dirs = chosen
		}
		for _, dir := range dirs {
			update(ctx, dir, []module.Module{m}, app.Hook)
			updated++
		}
	}
	return updated, errors.Join(errs...)
}

// chooseMembers asks which of the members requiring a module should have it
// upgraded. Whether the requirement is direct differs between members, so this
// cannot be decided once for the workspace.
func chooseMembers(mod module.Module, dirs, names []string, pageSize float64) ([]string, error) {
	options := slices.Clone(names)
	// Everything is selected to begin with, since upgrading a module
	// everywhere it is required is the usual intent.
	defaults := slices.Clone(options)

	prompt := &survey.MultiSelect{
		Message: fmt.Sprintf("Update %s to %s in which modules?",
			mod.Name, mod.To.Original()),
		Options:  options,
		Default:  defaults,
		PageSize: pageRows(pageSize),
	}
	var choice []int
	if err := survey.AskOne(prompt, &choice); err != nil {
		if errors.Is(err, term.InterruptErr) {
			log.Info("Bye")
			os.Exit(0)
		}
		return nil, err
	}

	// The prompt reports positions in the option list, which was built from
	// names in the same order as dirs.
	out := make([]string, 0, len(choice))
	for _, i := range choice {
		out = append(out, dirs[i])
	}
	return out, nil
}

// relativeTo shortens member directories to something readable, by naming them
// relative to the directory they share.
//
// The result is ordered to match dirs, so a choice made against these names can
// be mapped back to the directory it refers to.
func relativeTo(dirs []string, all []string) []string {
	base := commonDir(all)
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		name := dir
		if base != "" {
			if rel, err := filepath.Rel(base, dir); err == nil {
				name = rel
			}
		}
		out = append(out, name)
	}
	return out
}

// commonDir returns the longest path prefix shared by every directory.
func commonDir(dirs []string) string {
	if len(dirs) == 0 {
		return ""
	}
	base := dirs[0]
	for _, dir := range dirs[1:] {
		for base != "" && base != string(filepath.Separator) {
			if dir == base || strings.HasPrefix(dir, base+string(filepath.Separator)) {
				break
			}
			base = filepath.Dir(base)
		}
	}
	return base
}

// runDir offers the updates available in one module directory and reports how
// many modules were updated.
func (app *AppEnv) runDir(ctx context.Context, dir string, sorter module.Sort) (int, error) {
	modules, err := discoverModules(ctx, dir, app.Ignore, app.scope())
	if err != nil {
		return 0, err
	}
	if app.All {
		// Which modules an upgrade reaches is only worth reporting when the
		// whole graph is on offer; a direct requirement is reached by the
		// module being worked on and little else is informative.
		deps, err := reverseDeps(ctx, dir)
		if err != nil {
			return 0, err
		}
		for i := range modules {
			modules[i].RequiredBy = deps[modules[i].Name]
		}
	}
	if app.Vuln {
		// A scan that cannot complete reports nothing, which reads exactly
		// like a clean result, so the failure is returned rather than logged.
		vulns, err := scanVulnerabilities(ctx, dir)
		if err != nil {
			return 0, err
		}
		annotateVulns(modules, vulns)
	}
	supported, err := toolsSupported(ctx)
	if err != nil {
		return 0, err
	}
	log.WithFields(log.Fields{
		"supported": supported,
	}).Debug("Tool support")
	if supported {
		toolModules, err := discoverTools(ctx, dir, app.Ignore)
		if err != nil {
			return 0, err
		}
		modules = append(modules, toolModules...)
	}
	// Sort once the tool modules have been merged in, so the whole list
	// shares one order rather than tools trailing behind.
	slices.SortStableFunc(modules, sorter.Compare)
	if len(modules) == 0 {
		fmt.Println("All modules are up to date")
		return 0, nil
	}
	if app.List {
		listModules(modules)
		return 0, nil
	}
	if !app.Force {
		modules = choose(modules, app.PageSize)
	} else {
		log.Debug("Update all modules in non-interactive mode...")
	}
	update(ctx, dir, modules, app.Hook)
	return len(modules), nil
}

// workSync runs go work sync, which brings every module in the workspace onto
// the versions the workspace as a whole selects.
func workSync(ctx context.Context, dir string) error {
	log.WithField("dir", dir).Info("Synchronizing workspace")
	cmd := exec.CommandContext(ctx, "go", "work", "sync")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"out":   string(out),
		}).Error("Error while synchronizing workspace")
		return fmt.Errorf("error running go work sync: %w", err)
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

// nameBudget caps how much of the terminal the name column may claim. One
// unusually long module path would otherwise pad every row to its width and
// leave no room for anything after it.
const nameBudget = 0.55

// columnWidths returns the widths needed to align the name and current
// version columns. Names are measured with DisplayName, since FormatName
// writes colour escapes that would otherwise be counted as visible.
func columnWidths(modules []module.Module) (maxName, maxFrom int) {
	for _, x := range modules {
		maxName = max(maxName, len(x.DisplayName()))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
	if limit := int(float64(terminalWidth()) * nameBudget); maxName > limit {
		maxName = limit
	}
	return maxName, maxFrom
}

// terminalWidth reports the width of the output, falling back to a
// conventional one when it is not a terminal so that a redirected listing is
// still readable.
func terminalWidth() int {
	if w, _, err := xterm.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// terminalHeight reports the height of the output, falling back to a
// conventional one when it is not a terminal.
func terminalHeight() int {
	if _, h, err := xterm.GetSize(int(os.Stdout.Fd())); err == nil && h > 0 {
		return h
	}
	return 24
}

// pageRows converts the --pagesize value into a number of rows to show.
//
// A value of one or below is a share of the terminal height, so the prompt
// grows with the window; anything above one is that many rows. Some of the
// height belongs to the question, the filter help and the shell prompt that
// follows, so a share is taken of what is left rather than of the whole.
func pageRows(pageSize float64) int {
	const (
		reserved = 5
		minRows  = 3
	)
	available := max(terminalHeight()-reserved, 0)
	switch {
	case pageSize > 1:
		return int(pageSize)
	case pageSize > 0:
		return max(int(float64(available)*pageSize), minRows)
	default:
		// Zero or negative is meaningless, so fall back to the default share.
		return max(int(float64(available)*DefaultPageSize), minRows)
	}
}

// requiredByWidth returns the columns left for the required-by text once the
// other columns have taken their share, or 0 if nothing needs it.
func requiredByWidth(modules []module.Module, used int) int {
	for _, x := range modules {
		if len(x.RequiredBy) > 0 {
			return max(terminalWidth()-used, 0)
		}
	}
	return 0
}

func listModules(modules []module.Module) {
	maxName, maxFrom := columnWidths(modules)
	// name, space, from, " -> ", and the widest replacement version.
	maxTo := 0
	maxVuln := 0
	for _, x := range modules {
		maxTo = max(maxTo, len(x.To.String()))
		maxVuln = max(maxVuln, len(strings.Join(x.Vulns, ", ")))
	}
	rest := requiredByWidth(modules, maxName+1+maxFrom+4+maxTo+2+maxVuln)
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		line := fmt.Sprintf("%s %s -> %s", x.FormatName(maxName), from, x.FormatTo())
		if v := x.FormatVulns(maxVuln); v != "" {
			line += "  " + v
		}
		if by := x.FormatRequiredBy(rest); by != "" {
			line += "  " + by
		}
		_, err := fmt.Fprintln(color.Output, line)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
			}).Error("Error while listing module")
		}
	}
}

func choose(modules []module.Module, pageSize float64) []module.Module {
	maxName, maxFrom := columnWidths(modules)
	maxTo := 0
	maxVuln := 0
	for _, x := range modules {
		maxTo = max(maxTo, len(x.To.String()))
		maxVuln = max(maxVuln, len(strings.Join(x.Vulns, ", ")))
	}
	// The prompt indents each option, so leave room for its marker.
	rest := requiredByWidth(modules, maxName+1+maxFrom+4+maxTo+2+maxVuln+6)
	options := []string{}
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		option := fmt.Sprintf("%s %s -> %s", x.FormatName(maxName), from, x.FormatTo())
		if v := x.FormatVulns(maxVuln); v != "" {
			option += "  " + v
		}
		if by := x.FormatRequiredBy(rest); by != "" {
			option += "  " + by
		}
		options = append(options, option)
	}
	prompt := &MultiSelect{
		survey.MultiSelect{
			Message:  "Choose which modules to update",
			Options:  options,
			PageSize: pageRows(pageSize),
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
