package discover

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"

	"github.com/oligot/go-mod-upgrade/internal/cooldown"
)

// Versions reports the tagged versions of a module newer than after, in
// ascending order, together with their publish times. The method value
// satisfies [cooldown.Lookup].
func (d Discoverer) Versions(name string, after *semver.Version) ([]cooldown.VersionInfo, error) {
	out, err := d.Run(d.Dir, "list", "-m", "-versions", name)
	if err != nil {
		return nil, fmt.Errorf("error listing versions of %s: %w", name, err)
	}
	newer, err := parseVersions(out, after)
	if err != nil {
		return nil, fmt.Errorf("error parsing versions of %s: %w", name, err)
	}
	if len(newer) == 0 {
		// No tagged version above the current one, for example a module resolved
		// only through pseudo-versions. That is an expected state, not a failure:
		// an empty candidate list holds the module back without a warning.
		return nil, nil
	}

	queries := []string{"list", "-m", "-json"}
	for _, v := range newer {
		// Original preserves the v prefix, which is how go list reports versions.
		queries = append(queries, name+"@"+v.Original())
	}
	timesOut, err := d.Run(d.Dir, queries...)
	if err != nil {
		return nil, fmt.Errorf("error looking up publish times of %s: %w", name, err)
	}
	times, err := parseTimes(timesOut)
	if err != nil {
		return nil, fmt.Errorf("error parsing publish times of %s: %w", name, err)
	}

	versions := []cooldown.VersionInfo{}
	for _, v := range newer {
		versions = append(versions, cooldown.VersionInfo{Version: v, Time: times[v.Original()]})
	}
	return versions, nil
}

// parseVersions extracts from `go list -m -versions` output the versions above
// after, in ascending order. Unparseable versions are skipped rather than
// failing the lookup, and finding nothing newer is a normal outcome, not an
// error.
func parseVersions(out []byte, after *semver.Version) ([]*semver.Version, error) {
	// The output is the module path followed by its versions.
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return nil, errors.New("no module path in go list -m -versions output")
	}
	name := fields[0]

	newer := []*semver.Version{}
	for _, field := range fields[1:] {
		v, err := semver.NewVersion(field)
		if err != nil {
			log.WithFields(log.Fields{
				"name":    name,
				"version": field,
			}).Debug("Skipping unparseable version")
			continue
		}
		if !v.GreaterThan(after) {
			continue
		}
		newer = append(newer, v)
	}
	// go emits versions in ascending order, but picking the greatest version old
	// enough depends on that order, so don't leave it to another tool's output.
	sort.Sort(semver.Collection(newer))
	return newer, nil
}

// parseTimes maps each version in `go list -m -json` output to its publish
// time. A version whose time go couldn't determine maps to the zero time.
func parseTimes(out []byte) (map[string]time.Time, error) {
	times := map[string]time.Time{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var listed goListModule
		if err := dec.Decode(&listed); err != nil {
			return nil, err
		}
		times[listed.Version] = listed.Time
	}
	return times, nil
}
