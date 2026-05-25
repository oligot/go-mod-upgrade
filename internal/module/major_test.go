package module

import (
	"testing"
	"github.com/oligot/go-mod-upgrade/internal/api"
)

func TestFindMajorUpgrades(t *testing.T) {
	items := []api.APIVersionItem{
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
