package module

import (
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/api"
)

func TestFindMajorUpgrades(t *testing.T) {
	items := []api.VersionItem{
		{ModulePath: "github.com/foo/bar/v3", Version: "v3.1.0"},
		{ModulePath: "github.com/foo/bar/v3", Version: "v3.0.0"},
		{ModulePath: "github.com/foo/bar/v2", Version: "v2.5.0"},
		{ModulePath: "github.com/foo/bar/v2", Version: "v2.6.0-rc.1"},
		{ModulePath: "github.com/foo/bar", Version: "v1.5.0"},
	}

	upgrades, err := FindMajorUpgrades("github.com/foo/bar", "v1.2.0", items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(upgrades) != 2 {
		t.Fatalf("expected 2 upgrades, got %d", len(upgrades))
	}

	var foundV2, foundV3 bool
	for _, up := range upgrades {
		if up.To.Major() == 2 {
			foundV2 = true
			if up.Name != "github.com/foo/bar/v2" || up.To.String() != "2.5.0" {
				t.Errorf("unexpected v2 upgrade: %+v", up)
			}
		}
		if up.To.Major() == 3 {
			foundV3 = true
			if up.Name != "github.com/foo/bar/v3" || up.To.String() != "3.1.0" {
				t.Errorf("unexpected v3 upgrade: %+v", up)
			}
		}
	}

	if !foundV2 || !foundV3 {
		t.Errorf("did not find expected upgrades")
	}
}

func TestFindMajorUpgrades_SkipsUnrelatedModulePaths(t *testing.T) {
	items := []api.VersionItem{
		// Parent module that historically contained this sub-path — must be ignored.
		{ModulePath: "github.com/foo/bar", Version: "v1.5.0"},
		// The correct upgrade path for a v1 bump.
		{ModulePath: "github.com/foo/bar/sub", Version: "v1.0.0"},
	}

	upgrades, err := FindMajorUpgrades("github.com/foo/bar/sub", "v0.1.0", items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 1 || upgrades[0].Name != "github.com/foo/bar/sub" {
		t.Errorf("expected only github.com/foo/bar/sub upgrade, got %+v", upgrades)
	}
}

func TestFindMajorUpgrades_SkipsDeprecatedRetractedPrerelease(t *testing.T) {
	items := []api.VersionItem{
		{ModulePath: "github.com/foo/bar/v2", Version: "v2.0.0", Deprecated: true},
		{ModulePath: "github.com/foo/bar/v3", Version: "v3.0.0", Retracted: true},
		{ModulePath: "github.com/foo/bar/v4", Version: "v4.0.0-beta.1"},
	}

	upgrades, err := FindMajorUpgrades("github.com/foo/bar", "v1.0.0", items)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(upgrades) != 0 {
		t.Errorf("expected no upgrades, got %d: %+v", len(upgrades), upgrades)
	}
}

func TestMajorVersionPath(t *testing.T) {
	tests := []struct {
		currentPath string
		major       uint64
		expected    string
	}{
		{"github.com/foo/bar", 1, "github.com/foo/bar"},
		{"github.com/foo/bar", 2, "github.com/foo/bar/v2"},
		{"github.com/foo/bar/v2", 3, "github.com/foo/bar/v3"},
		{"github.com/foo/bar/sub", 1, "github.com/foo/bar/sub"},
		{"github.com/foo/bar/sub", 2, "github.com/foo/bar/sub/v2"},
	}
	for _, tt := range tests {
		got := majorVersionPath(tt.currentPath, tt.major)
		if got != tt.expected {
			t.Errorf("majorVersionPath(%q, %d) = %q, want %q", tt.currentPath, tt.major, got, tt.expected)
		}
	}
}
