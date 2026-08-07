package module

import (
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// PerConfiguration returns one row per configuration reaching a module, so that a
// module in the build under several is listed once for each.
//
// A listing has one line per row, and a module reached three ways would otherwise
// crowd three configurations into one cell. One row each answers the question a
// reader is actually asking -- which upgrade belongs to which build -- and leaves
// them to collapse the rows by eye, the sort having placed them together.
//
// What excludes a module is not one of those builds. "In the plain build, and lost
// once integration is set" is a single statement about a single build, so a negated
// configuration qualifies the rows rather than becoming one: split out, one row
// would claim the reach without the exclusion and the other the reverse.
//
// A row carries everything else the module did. None of it was gathered per
// configuration: what each sweep found is unioned before a module is annotated, so
// an advisory belongs to the module rather than to one of its rows, and dropping it
// from the others would read as though one build alone carried it.
//
// A module naming no configuration stays one row. Either every build reaches it or
// none does, and there is nothing to split.
func PerConfiguration(modules []Module) []Module {
	out := make([]Module, 0, len(modules))
	for _, mod := range modules {
		var reached, excluded []string
		for _, name := range mod.Tags {
			if strings.HasPrefix(name, "!") {
				excluded = append(excluded, name)
				continue
			}
			reached = append(reached, name)
		}
		if len(reached) <= 1 {
			out = append(out, mod)
			continue
		}
		for _, name := range reached {
			row := mod
			row.Tags = append([]string{name}, excluded...)
			out = append(out, row)
		}
	}
	return out
}

// PerRequirement returns one row per version the members of a workspace require,
// so that a module they disagree about is listed once for each version.
//
// From is the oldest of those versions, which is the right one to upgrade and the
// wrong one to report: it names a version the other members are already past, and
// gives a member at the newest version an upgrade it does not need. One row each
// states what each member actually requires.
//
// Every row keeps the same To. Which version is available is a property of the
// module rather than of any member, so all of them are offered the same one, and
// the row whose From already equals it has nothing to take -- which is what the
// delta filter reads to leave it out.
//
// RequiredBy narrows to the members requiring that row's version, that being what
// makes the row true. A module the members agree about stays one row, there being
// nothing to distinguish.
func PerRequirement(modules []Module) []Module {
	out := make([]Module, 0, len(modules))
	for _, mod := range modules {
		if len(mod.Required) <= 1 {
			out = append(out, mod)
			continue
		}
		for _, version := range sortedVersions(mod.Required) {
			row := mod
			// Parsed where it was recorded, so an unparseable key cannot lose a row:
			// the version came from a go.mod that the toolchain already read.
			if v, err := semver.NewVersion(version); err == nil {
				row.From = v
			}
			row.RequiredBy = slices.Clone(mod.Required[version])
			out = append(out, row)
		}
	}
	return out
}

// sortedVersions orders the versions of a requirement, oldest first, so that the
// rows of one module read in the order a listing sorts them.
//
// Ordered as versions rather than as strings: "v0.10.0" precedes "v0.9.0"
// alphabetically, which would print the newer requirement first.
func sortedVersions(required map[string][]string) []string {
	out := make([]string, 0, len(required))
	for version := range required {
		out = append(out, version)
	}
	slices.SortFunc(out, func(a, b string) int {
		x, errA := semver.NewVersion(a)
		y, errB := semver.NewVersion(b)
		if errA != nil || errB != nil {
			return strings.Compare(a, b)
		}
		return x.Compare(y)
	})
	return out
}

// JoinVersions names every version the members require, oldest first, for a
// listing that shows one row per module rather than one per requirement.
//
// A person reading a workspace wants one line per module, so the versions are
// crowded into the one cell: "0.3.0,0.40.0" says the members disagree, where
// "0.3.0" alone reports the members that are further ahead as further behind.
// Empty when they agree, leaving the ordinary single version to render.
func JoinVersions(required map[string][]string) string {
	if len(required) <= 1 {
		return ""
	}
	versions := sortedVersions(required)
	for i, version := range versions {
		if v, err := semver.NewVersion(version); err == nil {
			versions[i] = VersionText(v)
		}
	}
	return strings.Join(versions, ",")
}
