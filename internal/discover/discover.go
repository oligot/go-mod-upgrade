// Package discover finds outdated modules and tool modules with `go list`.
package discover

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// Runner runs the go command in dir and returns its standard output. Every
// implementation sets GOWORK=off; see [Exec].
type Runner func(dir string, args ...string) ([]byte, error)

// Exec is the one real Runner. Tests pass a closure instead.
func Exec(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(os.Environ(), "GOWORK=off")
	return cmd.Output()
}

// The `go list -f` templates. They live here as constants so the tests can
// assert which arguments get built without repeating them.
const (
	toolsFormat      = "{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}"
	toolUpdateFormat = "{{if .Update}}{{.Update.Version}}{{end}}"
)

// Discoverer lists the outdated modules of one module directory.
type Discoverer struct {
	Run    Runner
	Dir    string
	Ignore []*regexp.Regexp
}

// Modules returns the direct dependencies that have an update available.
func (d Discoverer) Modules() ([]module.Module, error) {
	list, err := d.Run(d.Dir, "list", "-m", "-u", "-mod=readonly", "-json", "all")
	if err != nil {
		return nil, fmt.Errorf("error running go command to discover modules: %w", err)
	}
	return parseModules(list, d.Ignore)
}

// Tools returns the module-backed tools that have an update available.
func (d Discoverer) Tools() ([]module.Module, error) {
	args := []string{"list", "-f", toolsFormat, "tool"}
	out, err := d.Run(d.Dir, args...)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"args":  append([]string{"go"}, args...),
		}).Error("error listing tools")
		return nil, fmt.Errorf("error listing tools: %w", err)
	}

	tools, err := parseTools(out)
	if err != nil {
		return nil, err
	}

	var modules []module.Module
	for _, t := range tools {
		// A tool whose update check fails is skipped, not fatal.
		updateOutput, err := d.Run(d.Dir, "list", "-m", "-f", toolUpdateFormat, "-u", t.path)
		if err != nil {
			continue
		}
		newVersion := strings.TrimSpace(string(updateOutput))
		if newVersion == "" || newVersion == t.version {
			continue
		}
		fromVersion, err := semver.NewVersion(t.version)
		if err != nil {
			return nil, fmt.Errorf("invalid tool version: %s -> %s: %w", t.path, t.version, err)
		}
		toVersion, err := semver.NewVersion(newVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid tool update version: %s -> %s: %w", t.path, newVersion, err)
		}
		log.WithFields(log.Fields{
			"tool": t.path,
			"from": t.version,
			"to":   newVersion,
		}).Debug("Found tool module update available")
		if shouldIgnore(t.path, t.version, newVersion, d.Ignore) {
			continue
		}
		modules = append(modules, module.Module{
			Name: t.path,
			From: fromVersion,
			To:   toVersion,
		})
	}

	return modules, nil
}

// ToolsSupported reports whether d.Dir's toolchain supports tool modules.
// `go version` selects its toolchain from the go.mod of the directory it runs
// in, so this has to be asked per module directory: in workspace mode members
// can pin toolchains straddling the 1.24 tool-module gate.
func (d Discoverer) ToolsSupported() (bool, error) {
	gv, err := d.Run(d.Dir, "version")
	if err != nil {
		return false, err
	}
	return parseGoVersion(gv)
}
