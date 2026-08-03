package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// goReleasesURL is where Go publishes its releases.
//
// The default endpoint reports only the supported ones -- the current release and the
// one before it -- which is the window this policy is about. Asking for everything would
// return three hundred entries and the release candidates among them.
const goReleasesURL = "https://go.dev/dl/?mode=json"

// release is one Go release as go.dev reports it.
type goRelease struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

// ParseReleases reads the supported Go releases from what go.dev publishes, newest
// first.
//
// The patch level is dropped: "the last two releases" is about 1.26 and 1.25, not about
// which patch anyone happens to be on, and several patches of one version are one
// release between them.
//
// An answer with nothing usable in it is an error rather than an empty window. An empty
// window would permit everything, so a policy asking about Go versions would silently
// stop asking -- which is the one failure mode a security setting must not have.
func ParseReleases(body []byte) ([]string, error) {
	var published []goRelease
	if err := json.Unmarshal(body, &published); err != nil {
		return nil, fmt.Errorf("reading Go releases: %w", err)
	}

	var supported []string
	seen := map[string]struct{}{}
	for _, r := range published {
		// A release candidate is not something a project can be required to support:
		// it is not released, and a floor derived from one would reject everything.
		if !r.Stable {
			continue
		}
		minor, err := goMinor(strings.TrimPrefix(r.Version, "go"))
		if err != nil {
			continue
		}
		if _, had := seen[minor]; had {
			continue
		}
		seen[minor] = struct{}{}
		supported = append(supported, minor)
	}
	if len(supported) == 0 {
		return nil, fmt.Errorf("no stable Go releases found at %s", goReleasesURL)
	}
	return supported, nil
}

// goMinor reduces a Go version to the release it belongs to, so "1.25.12" and "1.25" are
// the same answer.
func goMinor(version string) (string, error) {
	v, err := semver.NewVersion(version)
	if err != nil {
		return "", fmt.Errorf("version %q: %w", version, err)
	}
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor()), nil
}

// GoFloor returns the oldest Go release a policy supporting the last n permits.
//
// A count rather than a version, because the answer moves when Go releases. A policy
// naming a count says what it means once and stays correct; one naming 1.25 has to be
// edited every six months and is wrong in between.
//
// Asking for more releases than exist yields the oldest there is, which is the most
// permissive reading of what was asked and not an error: a policy supporting the last
// four releases during a period when Go publishes two is satisfied by anything.
func GoFloor(supported []string, last int) (string, error) {
	if last < 1 {
		return "", fmt.Errorf("go releases: %d is not a window; name how many releases to support", last)
	}
	if len(supported) == 0 {
		return "", fmt.Errorf("go releases: none known, so no floor can be set")
	}
	if last > len(supported) {
		last = len(supported)
	}
	return supported[last-1], nil
}

// GoSupported reports whether a declared Go version is inside the window.
//
// Two things are deliberately not failures. A version ahead of the window, since a
// project on a newer release is not what this policy is about. And a version that is
// missing or unreadable, since an unknown declaration is not an ancient one -- treating
// it as a breach would fail every module the toolchain said nothing about.
func GoSupported(declared, floor string) bool {
	if declared == "" {
		return true
	}
	at, err := semver.NewVersion(declared)
	if err != nil {
		return true
	}
	oldest, err := semver.NewVersion(floor)
	if err != nil {
		return true
	}
	// Compared on the release rather than the patch, since the window is a window of
	// releases: 1.25.12 and 1.25 are inside a floor of 1.25 alike.
	if at.Major() != oldest.Major() {
		return at.Major() > oldest.Major()
	}
	return at.Minor() >= oldest.Minor()
}
