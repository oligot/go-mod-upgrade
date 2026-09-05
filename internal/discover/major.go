package discover

import (
	"context"
	"math/rand/v2"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	xmodule "golang.org/x/mod/module"

	"github.com/oligot/go-mod-upgrade/internal/api"
	"github.com/oligot/go-mod-upgrade/internal/module"
)

// directDepsFormat lists every direct dependency as "path version".
const directDepsFormat = "{{if not (or .Main .Indirect)}}{{.Path}} {{.Version}}{{end}}"

// MajorUpgrades returns the major version upgrades available for d.Dir's direct
// dependencies, looked up through the pkg.go.dev API.
//
// Logging is returned rather than emitted: callers run this behind a spinner,
// and a log line written while the spinner is drawing corrupts the line. A
// failed lookup is never fatal — a module the API can't answer for is one that
// keeps its patch and minor upgrades.
func (d Discoverer) MajorUpgrades(noCache bool) ([]module.Module, []func()) {
	var logs []func()

	deps, err := d.DirectDependencies()
	if err != nil {
		return nil, []func(){func() {
			log.WithError(err).Warn("skipping major version check: failed to list direct dependencies")
		}}
	}
	before := len(deps)
	deps = filterPrivateModules(deps, d.goEnv("GOPRIVATE"))
	if skipped := before - len(deps); skipped > 0 {
		logs = append(logs, func() {
			log.WithField("count", skipped).Debug("skipped GOPRIVATE modules in major version check")
		})
	}
	logs = append(logs, func() {
		log.WithField("count", len(deps)).Debug("checked direct dependencies for major version upgrades")
	})

	upgrades, fetchLogs := fetchMajorUpgrades(deps, noCache)
	logs = append(logs, fetchLogs...)

	var kept []module.Module
	for _, up := range upgrades {
		if shouldIgnore(up.Name, up.From.String(), up.To.String(), d.Ignore) {
			continue
		}
		kept = append(kept, up)
	}
	return kept, logs
}

// DirectDependencies maps each direct dependency of d.Dir to its version.
func (d Discoverer) DirectDependencies() (map[string]string, error) {
	out, err := d.Run(d.Dir, "list", "-m", "-f", directDepsFormat, "all")
	if err != nil {
		return nil, err
	}
	return parseDirectDependencies(out), nil
}

// parseDirectDependencies turns "path version" lines into a map. Lines that
// aren't a pair are skipped: the template emits an empty line per module the
// filter rejects.
func parseDirectDependencies(out []byte) map[string]string {
	deps := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			deps[parts[0]] = parts[1]
		}
	}
	return deps
}

// goEnv returns the value of a `go env` variable, or "" if it can't be read.
// Not routed through d.Run: that sets GOWORK=off, which would report the
// workspace-off value of the variable rather than the one in effect.
func (d Discoverer) goEnv(name string) string {
	cmd := exec.Command("go", "env", name)
	cmd.Dir = d.Dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// filterPrivateModules drops modules matched by the GOPRIVATE pattern list
// so their paths are never sent to pkg.go.dev.
func filterPrivateModules(deps map[string]string, goprivate string) map[string]string {
	if goprivate == "" {
		return deps
	}
	public := make(map[string]string, len(deps))
	for path, ver := range deps {
		if !xmodule.MatchPrefixPatterns(goprivate, path) {
			public[path] = ver
		}
	}
	return public
}

// fetchMajorUpgrades asks pkg.go.dev about every dependency concurrently.
func fetchMajorUpgrades(directDeps map[string]string, noCache bool) ([]module.Module, []func()) {
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		results   []module.Module
		logs      []func()
		failures  int
		sem       = make(chan struct{}, 3) // limit concurrent pkg.go.dev requests
		apiClient = api.NewClient(noCache)
	)

	addLog := func(fn func()) {
		mu.Lock()
		logs = append(logs, fn)
		mu.Unlock()
	}

	for path, ver := range directDeps {
		wg.Add(1)
		go func(p, v string) {
			defer wg.Done()
			time.Sleep(time.Duration(rand.IntN(100)) * time.Millisecond)
			sem <- struct{}{}
			defer func() { <-sem }()

			items, err := apiClient.FetchModuleVersions(context.Background(), p)
			if err != nil {
				capturedErr := err
				mu.Lock()
				failures++
				mu.Unlock()
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "error": capturedErr}).Debug("failed to fetch major version candidates")
				})
				return
			}
			itemCount := len(items)
			addLog(func() {
				log.WithFields(log.Fields{"module": p, "count": itemCount}).Debug("fetched major version candidates")
			})

			upgrades, err := module.FindMajorUpgrades(p, v, items)
			if err != nil {
				capturedErr := err
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "error": capturedErr}).Debug("failed to find major upgrades")
				})
				return
			}
			if len(upgrades) > 0 {
				addLog(func() {
					log.WithFields(log.Fields{"module": p, "upgrades": len(upgrades)}).Debug("found major version upgrades")
				})
				mu.Lock()
				for _, up := range upgrades {
					up.IsMajorUpgrade = true
					up.OldName = p
					results = append(results, up)
				}
				mu.Unlock()
			}
		}(path, ver)
	}

	wg.Wait()
	if failures > 0 {
		n := failures
		logs = append(logs, func() {
			log.WithField("count", n).Warn("some major version lookups failed; run with --verbose for details")
		})
	}
	return results, logs
}
