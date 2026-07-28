package module

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

func padRight(str string, length int) string {
	if len(str) >= length {
		return str
	}
	return str + strings.Repeat(" ", length-len(str))
}

// indirectMarker is appended to the name of a module that is only required
// indirectly, so it can be told apart from a direct dependency in the list.
const indirectMarker = " (i)"

type Module struct {
	Name string
	From *semver.Version
	To   *semver.Version
	// Indirect reports whether the module is recorded in go.mod with an
	// "// indirect" comment rather than being imported directly.
	Indirect bool
	// RequiredBy names what pulls this module in. In workspace mode these
	// are the members that require it; otherwise they are the modules that
	// depend on it. It is empty when the relationship was not computed.
	RequiredBy []string
	// Vulns holds the identifiers of the advisories affecting the current
	// version, empty when none are known or none were looked for.
	Vulns []string
	// Reachable counts how many of those advisories cover code this module's
	// dependants actually reach. The rest are present but not called.
	Reachable int
}

// VulnCalled reports whether any advisory covers code that is reached.
func (mod *Module) VulnCalled() bool {
	return mod.Reachable > 0
}

// DisplayName returns the name as rendered, without colour escapes.
// Callers measure this to size the name column, since the escapes written by
// FormatName would otherwise be counted as visible characters.
func (mod *Module) DisplayName() string {
	if mod.Indirect {
		return mod.Name + indirectMarker
	}
	return mod.Name
}

// shorten trims the front of a module path to fit within length, since the
// trailing segments identify it better than the host does.
//
// The marker is plain ASCII so that its width in bytes matches its width in
// columns, which is what the surrounding alignment assumes.
func shorten(name string, length int) string {
	if length <= 0 || len(name) <= length {
		return name
	}
	const ellipsis = "..."
	if length <= len(ellipsis) {
		return name[len(name)-length:]
	}
	return ellipsis + name[len(name)-(length-len(ellipsis)):]
}

// changedRole names the colour for the leftmost part of the version that
// moves, which is the part that says how disruptive the upgrade is.
func (mod *Module) changedRole() string {
	from, to := mod.From, mod.To
	switch {
	case from.Major() != to.Major():
		return RoleToMajor
	case from.Minor() != to.Minor():
		return RoleToMinor
	case from.Patch() != to.Patch():
		return RoleToMicro
	default:
		return RoleToPrerelease
	}
}

func (mod *Module) FormatName(length int) string {
	name := mod.Name
	if !mod.Indirect {
		return paint(RoleName)(padRight(shorten(name, length), length))
	}
	// The marker has to survive shortening, since it is what distinguishes an
	// indirect requirement from a direct one.
	name = shorten(name, length-len(indirectMarker))
	// Pad outside the colour function: padRight measures with len, which
	// counts escape bytes, so colouring a padded string misaligns the column.
	pad := max(length-len(name)-len(indirectMarker), 0)
	return paint(RoleName)(name) + paint(RoleIndirect)(indirectMarker) + strings.Repeat(" ", pad)
}

// FormatRequiredBy renders what pulls the module in, shortened to fit within
// width columns. Entries are dropped from the end, where the ordering has put
// the least informative ones, and replaced by a count of what was left out.
func (mod *Module) FormatRequiredBy(width int) string {
	if len(mod.RequiredBy) == 0 {
		return ""
	}
	c := paint(RoleRequiredBy)

	// Try the whole list, then progressively fewer entries, and keep the
	// longest rendering that fits.
	for shown := len(mod.RequiredBy); shown > 0; shown-- {
		text := strings.Join(mod.RequiredBy[:shown], ", ")
		if left := len(mod.RequiredBy) - shown; left > 0 {
			text += fmt.Sprintf(" +%d more", left)
		}
		if len(text) <= width || shown == 1 {
			return c(text)
		}
	}
	return ""
}

// FormatVulns renders the identifiers of the advisories affecting the module,
// shortened to fit within width columns. Reachable advisories are shown in red
// and the rest in yellow, since one the code can reach demands more attention.
func (mod *Module) FormatVulns(width int) string {
	if len(mod.Vulns) == 0 {
		return ""
	}
	role := RoleCVE
	if mod.VulnCalled() {
		role = RoleCVEReachable
	}
	c := paint(role)
	for shown := len(mod.Vulns); shown > 0; shown-- {
		text := strings.Join(mod.Vulns[:shown], ", ")
		if left := len(mod.Vulns) - shown; left > 0 {
			text += fmt.Sprintf(" +%d", left)
		}
		if len(text) <= width || shown == 1 {
			return c(text)
		}
	}
	return ""
}

// FormatFrom renders the current version, highlighting the part the upgrade
// replaces in the same colour the new version uses for it.
//
// The two columns share that colour so the change reads as one thing seen
// twice; what distinguishes them is the unchanged prefix, which recedes
// further in the version being left behind.
func (mod *Module) FormatFrom(length int) string {
	plain, changed := mod.split(mod.From)
	pad := max(length-len(plain)-len(changed), 0)
	return paint(RoleFrom)(plain) + paint(mod.changedRole())(changed) + strings.Repeat(" ", pad)
}

// FormatTo renders the new version, colouring the leftmost part that changes
// and everything after it.
//
// Reading rightwards from the first change is what shows the scale of the
// upgrade: a new major leaves nothing of the old version intact, while a new
// patch leaves everything before it untouched.
func (mod *Module) FormatTo() string {
	plain, changed := mod.split(mod.To)
	return paint(RoleTo)(plain) + paint(mod.changedRole())(changed)
}

// split divides a version at the leftmost component that differs between the
// current and the new one, so both columns can highlight the same place.
func (mod *Module) split(v *semver.Version) (plain, changed string) {
	from, to := mod.From, mod.To

	var before, after strings.Builder
	at := &before
	if from.Major() != to.Major() {
		at = &after
	}
	fmt.Fprintf(at, "%d.", v.Major())

	if from.Minor() != to.Minor() {
		at = &after
	}
	fmt.Fprintf(at, "%d.", v.Minor())

	if from.Patch() != to.Patch() {
		at = &after
	}
	fmt.Fprintf(at, "%d", v.Patch())

	if v.Prerelease() != "" {
		if from.Prerelease() != to.Prerelease() {
			at = &after
		}
		fmt.Fprintf(at, "-%s", v.Prerelease())
	}
	if v.Metadata() != "" {
		fmt.Fprintf(at, "+%s", v.Metadata())
	}
	return before.String(), after.String()
}
