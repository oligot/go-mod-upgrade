package module

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/oligot/go-mod-upgrade/internal/api"
)

// FindMajorUpgrades finds higher stable major version updates for a module.
func FindMajorUpgrades(currentPath string, currentVerStr string, items []api.VersionItem) ([]Module, error) {
	currentVer, err := semver.NewVersion(currentVerStr)
	if err != nil {
		return nil, err
	}

	var (
		currentMajor  = currentVer.Major()
		latestByMajor = make(map[uint64]*semver.Version)
		pathToMajor   = make(map[uint64]string)
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

		if item.ModulePath != majorVersionPath(currentPath, major) {
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

	sort.Slice(upgrades, func(i, j int) bool {
		return upgrades[i].To.Major() < upgrades[j].To.Major()
	})

	return upgrades, nil
}

// majorVersionPath returns the expected module path for the given major version.
// For major <= 1 it returns the base path (stripping any existing /vN suffix).
// For major >= 2 it returns basePath/vN.
func majorVersionPath(currentPath string, major uint64) string {
	base := currentPath
	if i := strings.LastIndex(currentPath, "/v"); i > 0 {
		if _, err := strconv.ParseUint(currentPath[i+2:], 10, 64); err == nil {
			base = currentPath[:i]
		}
	}
	if major <= 1 {
		return base
	}
	return fmt.Sprintf("%s/v%d", base, major)
}
