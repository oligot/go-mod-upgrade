package cooldown

import (
	"errors"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/oligot/go-mod-upgrade/internal/module"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"bare number means days", "7", 7 * 24 * time.Hour, false},
		{"days suffix", "7d", 7 * 24 * time.Hour, false},
		{"hours suffix", "12h", 12 * time.Hour, false},
		{"minutes suffix", "30m", 30 * time.Minute, false},
		{"zero is valid", "0", 0, false},
		{"surrounding space", " 7d ", 7 * 24 * time.Hour, false},
		{"empty", "", 0, true},
		{"not a number", "x", 0, true},
		{"negative", "-1", 0, true},
		{"unknown suffix", "7w", 0, true},
		{"fractional", "1.5d", 0, true},
		{"suffix only", "d", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDuration(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseDuration(%q) = %s, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuration(%q) returned unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseDuration(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

// fixedNow is an arbitrary but fixed clock, so ages in tests are exact.
var fixedNow = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// testModule builds a module whose target version was published age ago.
func testModule(name, from, to string, age time.Duration) module.Module {
	return module.Module{
		Name:   name,
		From:   semver.MustParse(from),
		To:     semver.MustParse(to),
		ToTime: fixedNow.Add(-age),
	}
}

// fakeLookup returns canned versions and counts how often it was called.
type fakeLookup struct {
	versions map[string][]VersionInfo
	err      error
	calls    int
}

func (f *fakeLookup) lookup(name string, after *semver.Version) ([]VersionInfo, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.versions[name], nil
}

// version builds a VersionInfo published age ago.
func version(v string, age time.Duration) VersionInfo {
	return VersionInfo{Version: semver.MustParse(v), Time: fixedNow.Add(-age)}
}

const week = 7 * 24 * time.Hour

func TestFilterKeepsModulesOlderThanTheWindow(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.0.0", "v1.1.0", 30*24*time.Hour)}
	f := &fakeLookup{}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if len(kept) != 1 || kept[0].To.String() != "1.1.0" {
		t.Fatalf("kept = %v, want the module unchanged at 1.1.0", kept)
	}
	if kept[0].Cooldown != nil {
		t.Errorf("Cooldown = %v, want nil for an unaffected module", kept[0].Cooldown)
	}
	if len(held) != 0 {
		t.Errorf("held = %v, want none", held)
	}
	if f.calls != 0 {
		t.Errorf("lookup was called %d times, want 0 for the fast path", f.calls)
	}
}

func TestFilterFallsBackToGreatestVersionOldEnough(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.0.0", "v1.4.0", 2*24*time.Hour)}
	f := &fakeLookup{versions: map[string][]VersionInfo{
		"example.com/a": {
			version("v1.1.0", 60*24*time.Hour),
			version("v1.2.0", 30*24*time.Hour),
			version("v1.3.0", 3*24*time.Hour), // still inside the window
			version("v1.4.0", 2*24*time.Hour),
		},
	}}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if len(held) != 0 {
		t.Fatalf("held = %v, want none", held)
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %v, want 1 module", kept)
	}
	if kept[0].To.String() != "1.2.0" {
		t.Errorf("To = %s, want the greatest version older than the window, 1.2.0", kept[0].To)
	}
	if kept[0].ToTime != fixedNow.Add(-30*24*time.Hour) {
		t.Errorf("ToTime = %s, want the publish time of 1.2.0", kept[0].ToTime)
	}
	if kept[0].Cooldown == nil {
		t.Fatal("Cooldown = nil, want the withheld version recorded")
	}
	if kept[0].Cooldown.Version.String() != "1.4.0" {
		t.Errorf("Cooldown.Version = %s, want 1.4.0", kept[0].Cooldown.Version)
	}
	if kept[0].Cooldown.Age != 2*24*time.Hour {
		t.Errorf("Cooldown.Age = %s, want 48h", kept[0].Cooldown.Age)
	}
}

func TestFilterHoldsBackWhenNoVersionIsOldEnough(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.0.0", "v1.1.0", 2*24*time.Hour)}
	f := &fakeLookup{versions: map[string][]VersionInfo{
		"example.com/a": {version("v1.1.0", 2*24*time.Hour)},
	}}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if len(kept) != 0 {
		t.Errorf("kept = %v, want none", kept)
	}
	if len(held) != 1 {
		t.Fatalf("held = %v, want 1 module", held)
	}
	if held[0].Name != "example.com/a" || held[0].Version.String() != "1.1.0" {
		t.Errorf("held[0] = %+v, want example.com/a at 1.1.0", held[0])
	}
	if held[0].Age != 2*24*time.Hour {
		t.Errorf("held[0].Age = %s, want 48h", held[0].Age)
	}
}

func TestFilterNeverFallsBackToTheCurrentVersionOrBelow(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.2.0", "v1.3.0", 2*24*time.Hour)}
	f := &fakeLookup{versions: map[string][]VersionInfo{
		"example.com/a": {
			version("v1.1.0", 90*24*time.Hour),
			version("v1.2.0", 60*24*time.Hour),
			version("v1.3.0", 2*24*time.Hour),
		},
	}}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if len(kept) != 0 {
		t.Errorf("kept = %v, want none: 1.2.0 is the current version and 1.1.0 is a downgrade", kept)
	}
	if len(held) != 1 {
		t.Errorf("held = %v, want the module held back", held)
	}
}

func TestFilterHoldsBackWhenLookupFails(t *testing.T) {
	mods := []module.Module{
		testModule("example.com/broken", "v1.0.0", "v1.1.0", time.Hour),
		testModule("example.com/fine", "v2.0.0", "v2.1.0", 30*24*time.Hour),
	}
	f := &fakeLookup{err: errors.New("boom")}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if len(kept) != 1 || kept[0].Name != "example.com/fine" {
		t.Errorf("kept = %v, want only example.com/fine", kept)
	}
	if len(held) != 1 || held[0].Name != "example.com/broken" {
		t.Errorf("held = %v, want only example.com/broken", held)
	}
}

func TestFilterSkipsVersionsWithoutAPublishTime(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.0.0", "v1.3.0", 2*24*time.Hour)}
	f := &fakeLookup{versions: map[string][]VersionInfo{
		"example.com/a": {
			version("v1.1.0", 60*24*time.Hour),
			{Version: semver.MustParse("v1.2.0")}, // zero Time
			version("v1.3.0", 2*24*time.Hour),
		},
	}}

	kept, _ := Filter(mods, week, fixedNow, f.lookup)

	if len(kept) != 1 || kept[0].To.String() != "1.1.0" {
		t.Errorf("kept = %v, want a fallback to 1.1.0, skipping the timestamp-less 1.2.0", kept)
	}
}

func TestFilterHoldsBackWhenTheTargetPublishTimeIsUnknown(t *testing.T) {
	// go list omits Time when it can't determine it, so ToTime decodes to the
	// zero value. Subtracting it would yield an age of two millennia, waving the
	// version through unverified; the contract is to fail closed instead.
	mods := []module.Module{{
		Name: "example.com/a",
		From: semver.MustParse("v1.0.0"),
		To:   semver.MustParse("v1.1.0"),
	}}
	f := &fakeLookup{versions: map[string][]VersionInfo{
		"example.com/a": {version("v1.1.0", 60*24*time.Hour)},
	}}

	kept, held := Filter(mods, week, fixedNow, f.lookup)

	if f.calls != 1 {
		t.Errorf("lookup was called %d times, want 1: an unknown publish time must not take the fast path", f.calls)
	}
	if len(kept) != 0 {
		t.Errorf("kept = %v, want none: v1.1.0 is the target itself, so there is no lower fallback", kept)
	}
	if len(held) != 1 {
		t.Fatalf("held = %v, want the module held back", held)
	}
	if held[0].Age != 0 {
		t.Errorf("held[0].Age = %s, want 0 for an unknown publish time", held[0].Age)
	}
}

func TestFilterFallbackAndPrereleases(t *testing.T) {
	// go list -m -versions does list prerelease tags, and semver orders
	// v1.4.0-rc.1 below v1.4.0, so a prerelease is a fallback candidate. Users on
	// a stable version must not be offered one, since go list -u would never
	// propose it either.
	candidates := []VersionInfo{
		version("v1.3.0", 60*24*time.Hour),
		version("v1.4.0-rc.1", 30*24*time.Hour),
		version("v1.4.0", 2*24*time.Hour),
	}
	tests := []struct {
		name     string
		from     string
		to       string
		wantTo   string
		wantHeld bool
	}{
		{
			name:     "a stable current version never falls back to a prerelease",
			from:     "v1.3.0",
			to:       "v1.4.0",
			wantHeld: true,
		},
		{
			name:   "a prerelease current version may move within the prerelease line",
			from:   "v1.4.0-rc.0",
			to:     "v1.4.0",
			wantTo: "1.4.0-rc.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mods := []module.Module{testModule("example.com/a", tt.from, tt.to, 2*24*time.Hour)}
			f := &fakeLookup{versions: map[string][]VersionInfo{"example.com/a": candidates}}

			kept, held := Filter(mods, week, fixedNow, f.lookup)

			if tt.wantHeld {
				if len(kept) != 0 || len(held) != 1 {
					t.Fatalf("kept = %v, held = %v, want the module held back", kept, held)
				}
				return
			}
			if len(held) != 0 {
				t.Fatalf("held = %v, want none", held)
			}
			if len(kept) != 1 || kept[0].To.String() != tt.wantTo {
				t.Fatalf("kept = %v, want a fallback to %s", kept, tt.wantTo)
			}
		})
	}
}

func TestFilterIsANoOpWithoutAWindow(t *testing.T) {
	mods := []module.Module{testModule("example.com/a", "v1.0.0", "v1.1.0", time.Minute)}
	f := &fakeLookup{}

	kept, held := Filter(mods, 0, fixedNow, f.lookup)

	if len(kept) != 1 || kept[0].Cooldown != nil {
		t.Errorf("kept = %v, want the module untouched", kept)
	}
	if len(held) != 0 || f.calls != 0 {
		t.Errorf("held = %v, lookup calls = %d, want none of either", held, f.calls)
	}
}
