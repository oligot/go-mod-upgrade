package module

import (
	"github.com/Masterminds/semver/v3"
	"github.com/oligot/go-mod-upgrade/internal/api"
)

// FindMajorUpgrades finds higher stable major version updates for a module.
func FindMajorUpgrades(currentPath string, currentVerStr string, items []api.APIVersionItem) ([]Module, error) {
	currentVer, err := semver.NewVersion(currentVerStr)
	if err != nil {
		return nil, err
	}

	var (
		currentMajor = currentVer.Major()
		latestByMajor = make(map[uint64]*semver.Version)
		pathToMajor  = make(map[uint64]string)
	)

	for _, item := range items {
		if item.Deprecated || item.Retracted {
			continue
		}

		v, err := semver.NewVersion(item.Version)
		if err != nil {
			continue
		}

		if v.Prerelease() != "" {
			continue
		}

		major := v.Major()
		if major <= currentMajor {
			continue
		}

		if existing, ok := latestByMajor[major]; !ok || v.GreaterThan(existing) {
			latestByMajor[major] = v
			pathToMajor[major] = item.ModulePath
		}
	}

	var upgrades []Module
	for major, latestVer := range latestByMajor {
		upgrades = append(upgrades, Module{
			Name: pathToMajor[major],
			From: currentVer,
			To:   latestVer,
		})
	}

	return upgrades, nil
}
