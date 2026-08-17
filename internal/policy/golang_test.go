package policy

import (
	"slices"
	"strings"
	"testing"
)

// TestParseReleasesRejectsNothing checks that an empty or unusable answer is an error
// rather than an empty window.
//
// An empty window would permit everything, so a policy asking about Go versions would
// silently stop asking -- the failure mode a security setting must not have.
func TestParseReleasesRejectsNothing(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty list", `[]`},
		{"nothing stable", `[{"version": "go1.27rc1", "stable": false}]`},
		{"not json", `<html>503</html>`},
		{"unreadable versions", `[{"version": "tip", "stable": true}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseReleases(false, []byte(tc.body)); err == nil {
				t.Errorf("ParseReleases() = %v, want an error", got)
			}
		})
	}
}

// TestParseReleasesKeepsPatchesAndPrereleases checks that the whole published history
// survives, since a band counts patches and may be asked to include release candidates.
//
// The default go.dev endpoint reports only the two current releases, which is why a patch
// offset had nothing to count and failed with "nothing below 1.26.5 is published". Asking
// for everything is the fix, and then a prerelease has to stay distinguishable: normalising
// to major.minor.patch would collapse 1.27rc1 and 1.27rc2 into one entry and collide with a
// real 1.27.0.
func TestParseReleasesKeepsPatchesAndPrereleases(t *testing.T) {
	body := `[
      {"version": "go1.27rc2",  "stable": false},
      {"version": "go1.27rc1",  "stable": false},
      {"version": "go1.26.5",   "stable": true},
      {"version": "go1.26.4",   "stable": true},
      {"version": "go1.26",     "stable": true},
      {"version": "go1.25.12",  "stable": true}
    ]`

	got, err := ParseReleases(true, []byte(body))
	if err != nil {
		t.Fatalf("ParseReleases: %v", err)
	}
	// Newest first, prereleases kept and distinct from each other.
	want := []Release{
		{Version: "1.27.0-rc2", Prerelease: true},
		{Version: "1.27.0-rc1", Prerelease: true},
		{Version: "1.26.5"},
		{Version: "1.26.4"},
		{Version: "1.26.0"},
		{Version: "1.25.12"},
	}
	if len(got) != len(want) {
		t.Fatalf("ParseReleases() = %v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i].Version != want[i].Version || got[i].Prerelease != want[i].Prerelease {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Without prereleases, the same body yields only the stable ones.
	got, err = ParseReleases(false, []byte(body))
	if err != nil {
		t.Fatalf("ParseReleases: %v", err)
	}
	for _, r := range got {
		if r.Prerelease {
			t.Errorf("got %+v, want stable releases only", r)
		}
	}
	if len(got) != 4 {
		t.Errorf("got %d stable releases, want 4", len(got))
	}
}

// TestParseRelative reads a relative bound, where the operator carries the meaning.
//
// ">=2" says the two most recent releases are supported, so the bound is a floor two back
// from current. "<=2" says the opposite -- nothing newer than two back -- which is what a
// deliberately trailing shop asks for. The operator is required because "2" alone reads as
// "exactly two back" to some eyes and "within two" to others, and a policy should not be
// guessed at.
//
// No sign. Every stable release is at or below the current one, so an offset ahead of it can
// never match anything and the sign would carry no information.
func TestParseRelative(t *testing.T) {
	for _, tc := range []struct {
		spec  string
		want  Relative
		fails bool
	}{
		{spec: ">=2", want: Relative{Op: AtLeast, Count: 2, Set: true}},
		{spec: "<=3", want: Relative{Op: AtMost, Count: 3, Set: true}},
		{spec: "=1", want: Relative{Op: Exactly, Count: 1, Set: true}},
		// Zero is a real bound: ">=0" is the current release and nothing older.
		{spec: ">=0", want: Relative{Op: AtLeast, Count: 0, Set: true}},
		// Spaces are a typo, not a syntax.
		{spec: ">= 2", want: Relative{Op: AtLeast, Count: 2, Set: true}},
		// A bare number is refused rather than assumed.
		{spec: "2", fails: true},
		// A sign says nothing here, so it is refused rather than silently accepted.
		{spec: ">=-2", fails: true},
		{spec: ">=+2", fails: true},
		// Nonsense.
		{spec: "", fails: true},
		{spec: ">2", fails: true},
		{spec: "~2", fails: true},
		{spec: ">=two", fails: true},
		{spec: ">=", fails: true},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseRelative(tc.spec)
			if tc.fails {
				if err == nil {
					t.Errorf("ParseRelative(%q) = %+v, want an error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRelative(%q): %v", tc.spec, err)
			}
			if got != tc.want {
				t.Errorf("ParseRelative(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}

	// An unset bound reports so, since "said nothing" and "said zero" are different and
	// only the second should constrain anything.
	var unset Relative
	if unset.Set {
		t.Error("the zero Relative reports as set, want unset")
	}
}

// TestRelativeString checks that a bound renders back as what would parse to it, since a
// listing shows it and a reader may paste it into a policy.
func TestRelativeString(t *testing.T) {
	for _, spec := range []string{">=2", "<=3", "=1", ">=0"} {
		r, err := ParseRelative(spec)
		if err != nil {
			t.Fatalf("ParseRelative(%q): %v", spec, err)
		}
		if got := r.String(); got != spec {
			t.Errorf("String() = %q, want %q", got, spec)
		}
	}
}

// TestBandResolve works out the edges of the supported range from relative bounds.
//
// ">=2" on the minor means the two most recent minors are supported, so with 1.26.5 current
// the floor is the 1.25 line and the ceiling is the current release. A project has to sit
// inside that: declaring 1.26 breaks the promise by refusing to build for anyone on 1.25, and
// declaring 1.24 is outside the set entirely.
func TestBandResolve(t *testing.T) {
	// Newest first, as go.dev reports them.
	published := []string{
		"1.26.5", "1.26.4", "1.26.0",
		"1.25.12", "1.25.11", "1.25.0",
		"1.24.13", "1.24.0",
		"1.23.4",
	}

	for _, tc := range []struct {
		name              string
		band              Band
		wantFloor, wantTo string
	}{{
		// The two most recent minors: 1.26 and 1.25, so the floor is the oldest 1.25.
		name:      "two minors supported",
		band:      Band{Minor: []Relative{{Op: AtLeast, Count: 2, Set: true}}},
		wantFloor: "1.25.0",
		wantTo:    "1.26.5",
	}, {
		// Only the current minor.
		name:      "one minor supported",
		band:      Band{Minor: []Relative{{Op: AtLeast, Count: 1, Set: true}}},
		wantFloor: "1.26.0",
		wantTo:    "1.26.5",
	}, {
		// Trailing deliberately: the line two back and nothing newer. Not everything
		// older as well -- against the real 274 published releases that would put the
		// floor at Go 1.0, which is not a band anyone means.
		name:      "at most two minors back",
		band:      Band{Minor: []Relative{{Op: AtMost, Count: 2, Set: true}}},
		wantFloor: "1.24.0",
		wantTo:    "1.24.13",
	}, {
		// Pinned to one line.
		name:      "exactly one minor back",
		band:      Band{Minor: []Relative{{Op: Exactly, Count: 1, Set: true}}},
		wantFloor: "1.25.0",
		wantTo:    "1.25.12",
	}, {
		// A patch bound narrows within the minors already chosen.
		name: "two minors, at least two patches",
		band: Band{
			Minor: []Relative{{Op: AtLeast, Count: 2, Set: true}},
			Patch: []Relative{{Op: AtLeast, Count: 2, Set: true}},
		},
		wantFloor: "1.25.11",
		wantTo:    "1.26.5",
	}, {
		// Nothing said bounds nothing, so the whole published history is the band.
		name:      "unset",
		band:      Band{},
		wantFloor: "1.23.4",
		wantTo:    "1.26.5",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			floor, ceiling, err := tc.band.Resolve(published, nil)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if floor != tc.wantFloor || ceiling != tc.wantTo {
				t.Errorf("Resolve() = %q..%q, want %q..%q", floor, ceiling, tc.wantFloor, tc.wantTo)
			}
		})
	}

	// Nothing published cannot yield a band.
	if _, _, err := (Band{}).Resolve(nil, nil); err == nil {
		t.Error("Resolve(nil) succeeded, want an error with no releases known")
	}
}

// TestBandExcludesAffectedVersions checks that the floor rises past the versions carrying
// advisories, and that it lands on a version that is actually clean.
//
// This is the case the whole band exists for: "two minors old, and nothing with a known CVE".
// Against the real database the 1.25 line has advisories through 1.25.11 and is clean at
// 1.25.12, so the band becomes 1.25.12 upwards.
//
// The floor cannot simply be "the oldest fix", because a CVE is not a range with one edge. The
// clean set can have holes, so the floor is the oldest version that is genuinely clean.
func TestBandExcludesAffectedVersions(t *testing.T) {
	published := []string{"1.26.5", "1.25.12", "1.25.11", "1.25.10", "1.25.0"}
	// 1.25.0 through 1.25.11 are affected; 1.25.12 and 1.26.5 are not.
	unclean := func(v string) bool { return v != "1.25.12" && v != "1.26.5" }

	band := Band{
		Minor:      []Relative{{Op: AtLeast, Count: 2, Set: true}},
		ExcludeCVE: true,
	}
	floor, ceiling, err := band.Resolve(published, unclean)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if floor != "1.25.12" {
		t.Errorf("floor = %q, want 1.25.12: the oldest clean release in the band", floor)
	}
	if ceiling != "1.26.5" {
		t.Errorf("ceiling = %q, want 1.26.5", ceiling)
	}

	// Without the exclusion the floor is the minor boundary again, so the flag is what
	// moved it rather than something else.
	band.ExcludeCVE = false
	if floor, _, err = band.Resolve(published, unclean); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if floor != "1.25.0" {
		t.Errorf("floor = %q, want 1.25.0 with the exclusion off", floor)
	}

	// Everything affected leaves nothing to stand on, which is reported rather than
	// resolved to a version that is known to be vulnerable.
	band.ExcludeCVE = true
	if _, _, err := band.Resolve(published, func(string) bool { return true }); err == nil {
		t.Error("Resolve succeeded with every release affected, want an error")
	}
}

// TestBandAllows judges a declared version against the resolved edges.
func TestBandAllows(t *testing.T) {
	for _, tc := range []struct {
		declared string
		want     bool
	}{
		{declared: "1.25.12", want: true},
		{declared: "1.26.0", want: true},
		{declared: "1.26.5", want: true},
		// Below the floor.
		{declared: "1.25.11", want: false},
		{declared: "1.24.0", want: false},
		// Above the ceiling, which is what drops the consumers it promised.
		{declared: "1.27.0", want: false},
		// A minor without a patch means its zero patch, which is inside here.
		{declared: "1.26", want: true},
		// Nothing declared, and nothing readable, are not breaches.
		{declared: "", want: true},
		{declared: "tip", want: true},
	} {
		t.Run(tc.declared, func(t *testing.T) {
			if got := BandAllows(tc.declared, "1.25.12", "1.26.5"); got != tc.want {
				t.Errorf("BandAllows(%q) = %v, want %v", tc.declared, got, tc.want)
			}
		})
	}
}

// TestLoadGoBand checks that a policy can state the band it keeps, one bound at a time.
func TestLoadGoBand(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "go":      {"supported-minor": ">=2", "exclude-cve": true},
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "go-outside-band", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := p.GoBand()
	if !ok {
		t.Fatal("GoBand() reports unset, want the band")
	}
	if want := ([]Relative{{Op: AtLeast, Count: 2, Set: true}}); !slices.Equal(got.Minor, want) {
		t.Errorf("Minor = %+v, want %+v", got.Minor, want)
	}
	if !got.ExcludeCVE {
		t.Error("ExcludeCVE is false, want it set")
	}
	// A bound nobody named stays unset rather than defaulting to something.
	if len(got.Patch) > 0 {
		t.Errorf("Patch = %+v, want unset", got.Patch)
	}
	// And no version appears anywhere in the policy, which is the point of it.
	if strings.Contains(boundsText(got.Minor), ".") {
		t.Errorf("Minor renders %q, want a relative bound", boundsText(got.Minor))
	}
}

// TestLoadGoBandRejectsABareCount checks that a bound with no operator fails when the file is
// read, rather than being guessed at.
func TestLoadGoBandRejectsABareCount(t *testing.T) {
	for _, spec := range []string{`"2"`, `">2"`, `">=-2"`} {
		path := write(t, t.TempDir(), "policy.json", `{
          "go":      {"supported-minor": `+spec+`},
          "actions": {"fail": {"exit": 1}},
          "modules": {"**": {"allow": "*"}},
          "rules":   [{"when": "go-outside-band", "then": "fail"}]
        }`)
		_, err := Load([]string{path})
		if err == nil {
			t.Errorf("Load(supported-minor = %s) succeeded, want an error", spec)
			continue
		}
		if !strings.Contains(err.Error(), "supported-minor") {
			t.Errorf("error %q does not name the field", err)
		}
	}
}

// TestLoadNoGoBand checks that a policy silent about Go asks nothing.
func TestLoadNoGoBand(t *testing.T) {
	path := write(t, t.TempDir(), "policy.json", `{
      "actions": {"fail": {"exit": 1}},
      "modules": {"**": {"allow": "*"}},
      "rules":   [{"when": "denied", "then": "fail"}]
    }`)
	p, err := Load([]string{path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, ok := p.GoBand(); ok {
		t.Errorf("GoBand() = %+v, %v, want unset", got, ok)
	}
}

// TestParseBoundsCombinesWithAnd reads several bounds from one spec, intersecting them.
//
// A comma means AND here, as it already does for a module's version constraint elsewhere in a
// policy. ">=2, <=1" is how a band with two edges is written: the two most recent lines, and
// nothing newer than one back -- which is the 1.25 line alone.
func TestParseBoundsCombinesWithAnd(t *testing.T) {
	for _, tc := range []struct {
		spec  string
		want  []Relative
		fails bool
	}{{
		spec: ">=2, <=1",
		want: []Relative{
			{Op: AtLeast, Count: 2, Set: true},
			{Op: AtMost, Count: 1, Set: true},
		},
	}, {
		// One bound is the ordinary case and still parses.
		spec: ">=2",
		want: []Relative{{Op: AtLeast, Count: 2, Set: true}},
	}, {
		// Spacing is not syntax.
		spec: ">=3,<=1",
		want: []Relative{
			{Op: AtLeast, Count: 3, Set: true},
			{Op: AtMost, Count: 1, Set: true},
		},
	}, {
		// A bound that will not parse fails the whole spec rather than being skipped.
		spec:  ">=2, 1",
		fails: true,
	}, {
		spec:  "",
		fails: true,
	}, {
		// A trailing comma is a typo, not an empty bound.
		spec:  ">=2,",
		fails: true,
	}} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseBounds(tc.spec)
			if tc.fails {
				if err == nil {
					t.Errorf("ParseBounds(%q) = %v, want an error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBounds(%q): %v", tc.spec, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ParseBounds(%q) = %v, want %v", tc.spec, got, tc.want)
			}
		})
	}
}

// TestBandResolveIntersectsBounds checks that several bounds narrow the band together.
func TestBandResolveIntersectsBounds(t *testing.T) {
	published := []string{
		"1.26.5", "1.26.0",
		"1.25.12", "1.25.0",
		"1.24.13", "1.24.0",
		"1.23.4",
	}

	// The two most recent lines, and nothing newer than one back: the 1.25 line.
	band := Band{Minor: []Relative{
		{Op: AtLeast, Count: 2, Set: true},
		{Op: AtMost, Count: 1, Set: true},
	}}
	floor, ceiling, err := band.Resolve(published, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if floor != "1.25.0" || ceiling != "1.25.12" {
		t.Errorf("Resolve() = %q..%q, want 1.25.0..1.25.12", floor, ceiling)
	}

	// Bounds that cannot both hold leave nothing, which is reported rather than resolved
	// to an arbitrary edge.
	band.Minor = []Relative{
		{Op: AtMost, Count: 0, Set: true},  // the current line only
		{Op: Exactly, Count: 2, Set: true}, // and also two back
	}
	if _, _, err := band.Resolve(published, nil); err == nil {
		t.Error("Resolve succeeded with bounds that cannot both hold, want an error")
	}
}

// TestBandPrereleasesWidenRatherThanShift checks that allowing release candidates adds them to
// the band without moving what counts as the current release.
//
// Counting from the newest published version, an RC becomes "current" the moment one exists,
// so ">=1" would resolve to the RC line alone and a project on the newest stable release would
// read as outside the band. Allowing prereleases has to widen the ceiling, not shift the whole
// band off the stable lines.
func TestBandPrereleasesWidenRatherThanShift(t *testing.T) {
	// As go.dev reports it: the RC leads, since it is the newest thing published.
	published := []string{"1.27.0-rc2", "1.27.0-rc1", "1.26.5", "1.26.0", "1.25.12", "1.25.0"}

	band := Band{Minor: []Relative{{Op: AtLeast, Count: 1, Set: true}}, AllowPrerelease: true}
	floor, ceiling, err := band.Resolve(published, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The current line is still 1.26, counted from the newest stable release.
	if floor != "1.26.0" {
		t.Errorf("floor = %q, want 1.26.0: the current stable line", floor)
	}
	// But the ceiling reaches the RC, which is what allowing them means.
	if ceiling != "1.27.0-rc2" {
		t.Errorf("ceiling = %q, want 1.27.0-rc2", ceiling)
	}
	// So a project on the newest stable release is inside the band, which it was not when
	// the RC counted as current.
	if !BandAllows("1.26.5", floor, ceiling) {
		t.Error("1.26.5 is outside the band, want the newest stable release inside it")
	}
}

// TestBandAllowsReadsGoReleaseNames checks that a go directive naming a release candidate is
// judged rather than waved through.
//
// Go writes "1.27rc2" where semver wants "1.27.0-rc2", so a directive naming an RC does not
// parse -- and the rule that an unparseable version is not a breach would let it past every
// band. The version is not unknown, though; it is a Go release name, and translating it is
// what the release list already does.
func TestBandAllowsReadsGoReleaseNames(t *testing.T) {
	// An RC above the ceiling is outside the band.
	if BandAllows("1.27rc2", "1.25.0", "1.26.5") {
		t.Error("1.27rc2 reads as inside 1.25.0..1.26.5, want it above the ceiling")
	}
	// And inside one that reaches it.
	if !BandAllows("1.27rc2", "1.26.0", "1.27.0-rc2") {
		t.Error("1.27rc2 reads as outside 1.26.0..1.27.0-rc2, want it at the ceiling")
	}
	// A directive with no patch still means its zero patch.
	if !BandAllows("1.26", "1.26.0", "1.26.5") {
		t.Error("1.26 reads as outside its own line, want 1.26.0")
	}
	// Something genuinely unreadable is still not a breach, since an unknown declaration
	// is not a broken promise.
	if !BandAllows("tip", "1.25.0", "1.26.5") {
		t.Error("an unreadable version reads as a breach, want it waved through")
	}
}
