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

// goSemver translates a Go release name into something semver can read.
//
// Go glues a prerelease on without a separator -- "go1.27rc2" rather than "go1.27.0-rc2" --
// which is not valid semver, so an RC would be skipped as unparseable. The minor line also
// omits its patch: "go1.26" means 1.26.0.
func goSemver(name string) string {
	v := strings.TrimPrefix(name, "go")
	// The prerelease starts at the first character that is neither a digit nor a dot.
	at := strings.IndexFunc(v, func(r rune) bool {
		return (r < '0' || r > '9') && r != '.'
	})
	if at < 0 {
		return v
	}
	release, pre := v[:at], v[at:]
	// "1.27" needs its patch before a prerelease can be appended to it.
	if strings.Count(release, ".") < 2 {
		release += strings.Repeat(".0", 2-strings.Count(release, "."))
	}
	return release + "-" + pre
}

// Release is one published Go release.
//
// Prerelease is kept rather than inferred from the version string, since the string is what
// go.dev gave and its own "stable" flag is the authority on what is released.
type Release struct {
	Version    string
	Prerelease bool
}

// ParseReleases reads the published Go releases from what go.dev publishes, newest first.
//
// Full versions, patch level and prerelease and all. A band counts patches, so it has to
// know that 1.26.4 exists -- and a prerelease has to stay distinguishable from its release,
// since normalising to major.minor.patch would collapse 1.27rc1 and 1.27rc2 into one entry
// and collide with a real 1.27.0.
//
// prereleases says whether to keep them at all. A release candidate is not something a
// project can ordinarily be required to support, so they are excluded unless asked for.
//
// An answer with nothing usable in it is an error rather than an empty window. An empty
// window would permit everything, so a policy asking about Go versions would silently
// stop asking -- which is the one failure mode a security setting must not have.
func ParseReleases(prereleases bool, body []byte) ([]Release, error) {
	var published []goRelease
	if err := json.Unmarshal(body, &published); err != nil {
		return nil, fmt.Errorf("reading Go releases: %w", err)
	}

	var found []Release
	seen := map[string]struct{}{}
	for _, r := range published {
		if !r.Stable && !prereleases {
			continue
		}
		v, err := semver.NewVersion(goSemver(r.Version))
		if err != nil {
			continue
		}
		// Normalised so "1.26" and "1.26.0" are one entry, with the prerelease kept so
		// "1.27rc1" and "1.27rc2" stay two.
		full := fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch())
		if pre := v.Prerelease(); pre != "" {
			full += "-" + pre
		}
		if _, had := seen[full]; had {
			continue
		}
		seen[full] = struct{}{}
		found = append(found, Release{Version: full, Prerelease: !r.Stable})
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no Go releases found at %s", goReleasesURL)
	}
	return found, nil
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

// GoBelow reports whether a declared Go version is older than a floor.
//
// The opposite question to GoWithinLookback, and the two coexist: one asks whether a
// project demands too much of its consumers, the other whether it demands too little for
// itself. Compared on the release, since "go 1.25.4" declares 1.25.
//
// A missing or unreadable version is not below anything, for the same reason it is not
// above anything: an unknown declaration is not a breach.
func GoBelow(declared, floor string) bool {
	if declared == "" {
		return false
	}
	at, err := semver.NewVersion(declared)
	if err != nil {
		return false
	}
	oldest, err := semver.NewVersion(floor)
	if err != nil {
		return false
	}
	if at.Major() != oldest.Major() {
		return at.Major() < oldest.Major()
	}
	return at.Minor() < oldest.Minor()
}

// Channel is how far behind the current release a project stays.
//
// Each offset applies to its own component of the newest published version and bounds the
// go directive from ABOVE. "go 1.26" is a demand on whoever builds the module, so declaring
// it drops every consumer still on 1.25 -- a project supporting two minors back must
// declare the older release, not the newer.
//
// Offsets rather than a count because the algebra is then explicit: a count cannot say
// whether "two back" means minors or patches, and the two are different promises. Zero
// everywhere is the current release exactly.
type Channel struct {
	Major int `json:"supported-major"`
	Minor int `json:"supported-minor"`
	Patch int `json:"supported-patch"`
}

// Set reports whether the channel says anything, so a policy that named no offsets asks
// nothing rather than pinning the project to today's release.
func (c Channel) Set() bool { return c.Major != 0 || c.Minor != 0 || c.Patch != 0 }

// Ceiling returns the newest version the channel permits, given the published releases
// newest first.
//
// The components below an offset one come from the release the offset lands on rather than
// from today: two minors back means the newest patch of that minor, since a patch level
// carried across from the current release may never have existed there.
//
// Reaching further back than anything published yields the oldest known. That is the most
// permissive reading of what was asked, and beats naming a version Go never shipped.
func (c Channel) Ceiling(published []string) (string, error) {
	if c.Major > 0 || c.Minor > 0 || c.Patch > 0 {
		return "", fmt.Errorf("go channel: offsets say how far behind the current release to stay, so %+v cannot be ahead of it", c)
	}
	if len(published) == 0 {
		return "", fmt.Errorf("go channel: no releases known, so no ceiling can be set")
	}
	current, err := semver.NewVersion(published[0])
	if err != nil {
		return "", fmt.Errorf("go channel: newest release %q: %w", published[0], err)
	}

	// Step back one component at a time, each from where the last one landed, so the
	// lower components always belong to the release actually reached.
	at := current
	for _, step := range []struct {
		name   string
		offset int
		back   func(*semver.Version, *semver.Version) bool
	}{
		{"supported-major", c.Major, func(v, from *semver.Version) bool { return v.Major() < from.Major() }},
		{"supported-minor", c.Minor, func(v, from *semver.Version) bool {
			return v.Minor() < from.Minor() || v.Major() < from.Major()
		}},
		{"supported-patch", c.Patch, func(v, from *semver.Version) bool { return v.LessThan(from) }},
	} {
		for i := range -step.offset {
			next := oldestBelow(published, at, step.back)
			if next == nil {
				// A component with nothing published below it cannot step back at
				// all, which means the offset asked for something that does not
				// exist. Reported rather than ignored: silently treating it as the
				// current release is the opposite of what was asked.
				if i == 0 {
					return "", fmt.Errorf("go channel: %s cannot go back %d, since nothing below %s is published",
						step.name, -step.offset, at)
				}
				// Further back than exists, having already stepped: the oldest known
				// is the most permissive reading of what was asked.
				break
			}
			at = next
		}
	}
	return fmt.Sprintf("%d.%d.%d", at.Major(), at.Minor(), at.Patch()), nil
}

// oldestBelow returns the newest published version that back reports as a step back from
// at, or nil when none is.
func oldestBelow(published []string, at *semver.Version, back func(v, from *semver.Version) bool) *semver.Version {
	for _, p := range published {
		v, err := semver.NewVersion(p)
		if err != nil {
			continue
		}
		if back(v, at) {
			return v
		}
	}
	return nil
}

// ChannelAllows reports whether a declared version is at or below the ceiling.
//
// Older than the ceiling is not a breach: a project further back than it promised still
// builds for everyone in the window, and is merely conservative. Newer is the breach, since
// it drops consumers the project said it supported.
//
// A version that is missing or unreadable is not a breach either, since an unknown
// declaration is not a broken promise.
func ChannelAllows(declared, ceiling string) bool {
	if declared == "" {
		return true
	}
	at, err := semver.NewVersion(declared)
	if err != nil {
		return true
	}
	top, err := semver.NewVersion(ceiling)
	if err != nil {
		return true
	}
	return !at.GreaterThan(top)
}
