package policy

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
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

// The operators a relative bound can use.
//
// Each says which edge of the supported range the count describes, which a bare number
// cannot: ">=2" supports the two most recent releases, while "<=2" refuses anything newer
// than two back. Both are real policies and they are opposites.
const (
	// AtLeast supports the counted releases and everything newer, so the count is a floor.
	AtLeast = ">="
	// AtMost refuses anything newer than the counted release, so the count is a ceiling.
	AtMost = "<="
	// Exactly supports only the counted release line.
	Exactly = "="
)

// Relative is a bound stated as a count of releases back from the current one.
//
// Relative rather than absolute so the answer moves when Go releases: a policy naming 1.25
// is wrong within six months and has to be edited on a schedule nobody remembers.
//
// Set distinguishes "said nothing" from "said zero", which are different -- ">=0" is the
// current release and nothing older, while an absent bound constrains nothing.
type Relative struct {
	Op    string
	Count int
	Set   bool
}

// String renders the bound as what would parse back to it, since a report shows it and a
// reader may paste it into a policy.
func (r Relative) String() string {
	if !r.Set {
		return ""
	}
	return r.Op + strconv.Itoa(r.Count)
}

// ParseRelative reads a relative bound.
//
// The operator is required. A bare "2" reads as "exactly two back" to some eyes and "within
// two" to others, and a policy is not a thing to guess at.
//
// No sign either. Every stable release is at or below the current one, so an offset ahead of
// it can never match anything -- a sign would carry no information and invite the reader to
// think it did.
func ParseRelative(spec string) (Relative, error) {
	text := strings.TrimSpace(spec)
	for _, op := range []string{AtLeast, AtMost, Exactly} {
		rest, found := strings.CutPrefix(text, op)
		if !found {
			continue
		}
		rest = strings.TrimSpace(rest)
		// Atoi accepts a sign, which says nothing here: every stable release is at or
		// below the current one, so an offset cannot be ahead of it. Refused rather
		// than silently accepted, since a reader who wrote one meant something by it.
		if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, "-") {
			return Relative{}, fmt.Errorf("relative bound %q: a count is how many releases back, so it takes no sign", spec)
		}
		count, err := strconv.Atoi(rest)
		if err != nil {
			return Relative{}, fmt.Errorf("relative bound %q: %q is not a count of releases", spec, rest)
		}
		if count < 0 {
			return Relative{}, fmt.Errorf("relative bound %q: a count is how many releases back, so it cannot be negative", spec)
		}
		return Relative{Op: op, Count: count, Set: true}, nil
	}
	return Relative{}, fmt.Errorf("relative bound %q: write it as %s2, %s2 or %s2, naming how many releases back",
		spec, AtLeast, AtMost, Exactly)
}

// Band is the range of Go versions a project supports, stated relatively.
//
// The bounds describe minors and patches separately, since how far behind a project stays in
// release lines is a different promise from how far behind it stays in fixes.
type Band struct {
	Minor Relative
	Patch Relative
	// ExcludeCVE raises the floor past any release carrying a known advisory. A band is a
	// promise about conservatism, and a version with a known hole is not a version to
	// stand on however old and settled it is.
	ExcludeCVE bool
	// AllowPrerelease keeps release candidates in the band. Off by default, since an RC is
	// not something a project can ordinarily be required to support.
	AllowPrerelease bool
}

// Set reports whether the band says anything at all.
func (b Band) Set() bool { return b.Minor.Set || b.Patch.Set || b.ExcludeCVE }

// Resolve works out the edges of the band from the published releases, newest first.
//
// unclean reports whether a version carries a known advisory, and is consulted only when
// ExcludeCVE is set. It is a predicate rather than a floor because an advisory is not a range
// with one edge: the clean set can have holes, so the floor is the oldest version that is
// genuinely clean rather than the oldest fix of anything.
//
// Both edges are returned, since the go directive has to sit between them: too new drops the
// consumers the project promised to support, and too old is outside the set entirely.
func (b Band) Resolve(published []string, unclean func(string) bool) (floor, ceiling string, err error) {
	if len(published) == 0 {
		return "", "", fmt.Errorf("go band: no releases known, so no band can be resolved")
	}

	// The minor lines, newest first, which is what a minor bound counts.
	var lines []string
	seen := map[string]struct{}{}
	for _, v := range published {
		minor, err := goMinor(v)
		if err != nil {
			continue
		}
		if _, had := seen[minor]; !had {
			seen[minor] = struct{}{}
			lines = append(lines, minor)
		}
	}
	if len(lines) == 0 {
		return "", "", fmt.Errorf("go band: no readable releases among %d published", len(published))
	}

	// Which lines the minor bound admits.
	newest, oldest := 0, len(lines)-1
	if b.Minor.Set {
		switch b.Minor.Op {
		case AtLeast:
			// The counted lines and everything newer.
			oldest = min(max(b.Minor.Count-1, 0), len(lines)-1)
		case AtMost:
			// The counted line and nothing newer. Not everything older too: with 274
			// releases published that would put the floor at Go 1.0, which is not a
			// band anyone means by "we trail by two".
			newest = min(b.Minor.Count, len(lines)-1)
			oldest = newest
		case Exactly:
			newest = min(b.Minor.Count, len(lines)-1)
			oldest = newest
		}
	}

	// Every release inside those lines, newest first.
	admitted := make([]string, 0, len(published))
	for _, v := range published {
		minor, err := goMinor(v)
		if err != nil {
			continue
		}
		at := slices.Index(lines, minor)
		if at < newest || at > oldest {
			continue
		}
		admitted = append(admitted, v)
	}
	if len(admitted) == 0 {
		return "", "", fmt.Errorf("go band: nothing published in the %s lines the band names", b.Minor)
	}

	ceiling = admitted[0]
	floor = admitted[len(admitted)-1]

	// A patch bound raises the floor within its own line rather than counting across the
	// whole admitted set. Counted globally it would swallow entire minors: two patches back
	// from 1.26.5 is 1.26.4, which would discard the 1.25 line the minor bound just
	// admitted. So the line the floor sits in is the one narrowed.
	if b.Patch.Set {
		line, err := goMinor(floor)
		if err != nil {
			return "", "", fmt.Errorf("go band: floor %q: %w", floor, err)
		}
		var inLine []string
		for _, v := range admitted {
			if at, err := goMinor(v); err == nil && at == line {
				inLine = append(inLine, v)
			}
		}
		switch b.Patch.Op {
		case AtLeast:
			inLine = inLine[:min(max(b.Patch.Count, 1), len(inLine))]
		case AtMost:
			inLine = inLine[min(b.Patch.Count, len(inLine)-1):]
		case Exactly:
			at := min(b.Patch.Count, len(inLine)-1)
			inLine = inLine[at : at+1]
		}
		floor = inLine[len(inLine)-1]
		// Everything below the new floor leaves the admitted set, so the exclusion walk
		// below does not reach past it.
		admitted = admitted[:slices.Index(admitted, floor)+1]
	}

	// The floor rises past anything carrying an advisory. Walked from the oldest upwards,
	// so it lands on a version that is itself clean rather than merely above some fix.
	if b.ExcludeCVE && unclean != nil {
		floor = ""
		for i := len(admitted) - 1; i >= 0; i-- {
			if !unclean(admitted[i]) {
				floor = admitted[i]
				break
			}
		}
		if floor == "" {
			return "", "", fmt.Errorf("go band: every release the band admits carries a known advisory, so there is nothing to stand on")
		}
	}
	return floor, ceiling, nil
}

// BandAllows reports whether a declared version sits inside the band.
//
// Two things are deliberately not breaches: a version that is missing, and one that will not
// parse. An unknown declaration is not a broken promise, and treating it as one would fail
// every module the toolchain said nothing about.
func BandAllows(declared, floor, ceiling string) bool {
	if declared == "" {
		return true
	}
	at, err := semver.NewVersion(declared)
	if err != nil {
		return true
	}
	bottom, err := semver.NewVersion(floor)
	if err != nil {
		return true
	}
	top, err := semver.NewVersion(ceiling)
	if err != nil {
		return true
	}
	return !at.LessThan(bottom) && !at.GreaterThan(top)
}
