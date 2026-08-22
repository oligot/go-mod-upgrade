package discover

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/fatih/color"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// tool is a module-backed tool named by `go list ... tool`.
type tool struct {
	path    string
	version string
}

// goListModule is the subset of `go list -m -json` output that we use.
type goListModule struct {
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Update   *goListModule
}

// parseModules turns `go list -m -json` output into modules, dropping ignored
// ones. The output is a stream of concatenated objects, not an array.
func parseModules(out []byte, ignore []*regexp.Regexp) ([]module.Module, error) {
	modules := []module.Module{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var listed goListModule
		if err := dec.Decode(&listed); err != nil {
			return nil, fmt.Errorf("error parsing go list output: %w", err)
		}
		if listed.Main || listed.Indirect || listed.Update == nil {
			continue
		}
		name, from, to := listed.Path, listed.Version, listed.Update.Version
		log.WithFields(log.Fields{
			"name": name,
			"from": from,
			"to":   to,
		}).Debug("Found module")
		if shouldIgnore(name, from, to, ignore) {
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
		modules = append(modules, module.Module{
			Name: name,
			From: fromversion,
			To:   toversion,
		})
	}
	return modules, nil
}

// parseTools turns `go list -f ... tool` output into tool paths and versions.
// Tools with no module — local ones — are skipped.
func parseTools(out []byte) ([]tool, error) {
	var tools []tool
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 1 {
			continue // local tool
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tool format: %s", line)
		}
		tools = append(tools, tool{path: parts[0], version: parts[1]})
	}
	return tools, nil
}

// parseGoVersion reports whether `go version` output names a toolchain that
// supports tool modules.
func parseGoVersion(out []byte) (bool, error) {
	version := strings.TrimSpace(string(out))
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

// CompileIgnore compiles the --ignore patterns, rejecting invalid ones up
// front rather than per module.
func CompileIgnore(patterns []string) ([]*regexp.Regexp, error) {
	res := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid --ignore pattern %q: %w", p, err)
		}
		res = append(res, re)
	}
	return res, nil
}

func shouldIgnore(name, from, to string, ignore []*regexp.Regexp) bool {
	for _, re := range ignore {
		if re.MatchString(name) {
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
