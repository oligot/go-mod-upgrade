package module

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// The marks that can appear beside a module's name. They sit there because each
// describes the module itself rather than the step between two versions, which
// is what the rest of the row is about.
//
// They are gathered into one parenthesised group, so a row carries one piece of
// punctuation however many marks apply: "(i)", "(DA)", "(iDA)". Each is a single
// letter so several fit without crowding the row -- a module can be required
// indirectly, deprecated by its author, and marked archived by a reviewer all at
// once.
const (
	// indirectMark distinguishes a requirement reached only through another
	// module from one the code imports directly.
	indirectMark = "i"
	// deprecatedMark is the author deprecating the module.
	deprecatedMark = "D"
	// retractedMark is the author withdrawing the version in use.
	retractedMark = "R"
	// archivedMark is a policy asserting the module is abandoned.
	archivedMark = "A"
)

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
	// Ignored reports whether --ignore matched the module. Such a module is
	// withheld from the upgrade list but still checked against a policy, since
	// declining an upgrade is not the same as exempting it from review.
	Ignored bool
	// Deprecated carries the author's deprecation message, empty when the
	// module declares none. It describes the module rather than one version, so
	// an upgrade does not resolve it.
	Deprecated string
	// Retracted holds the author's reasons for withdrawing the version in use,
	// empty when it stands. Unlike a deprecation this is per version, so an
	// upgrade can resolve it.
	Retracted []string
	// Archived is the reason a policy gave for considering the module
	// abandoned, empty when none did. Unlike the two above it is asserted
	// rather than observed, so it arrives from the policy rather than from the
	// toolchain.
	Archived string
}

// IsDeprecated reports whether the author has deprecated the module.
func (mod *Module) IsDeprecated() bool { return mod.Deprecated != "" }

// IsRetracted reports whether the author has withdrawn the version in use.
func (mod *Module) IsRetracted() bool { return len(mod.Retracted) > 0 }

// IsArchived reports whether a policy asserts the module is abandoned.
func (mod *Module) IsArchived() bool { return mod.Archived != "" }

// Disowned reports whether the module has been given up on, by its author or by
// a reviewer. Such a module is worth attention whatever its version says.
func (mod *Module) Disowned() bool {
	return mod.IsDeprecated() || mod.IsRetracted() || mod.IsArchived()
}

// VulnCalled reports whether any advisory covers code that is reached.
func (mod *Module) VulnCalled() bool {
	return mod.Reachable > 0
}

// mark is one letter beside a module's name, and the role colouring it.
type mark struct {
	letter string
	role   string
}

// marks returns what appears in the parenthesised group beside the name.
//
// How the module is required comes first, since it is the oldest of these and
// the one always worth knowing. Then what its author said about it, and last
// what a reviewer asserted: an observation outranks an assertion, and upstream
// speaking about itself outranks either.
func (mod *Module) marks() []mark {
	var marks []mark
	if mod.Indirect {
		marks = append(marks, mark{indirectMark, RoleIndirect})
	}
	if mod.IsDeprecated() {
		marks = append(marks, mark{deprecatedMark, RoleDeprecated})
	}
	if mod.IsRetracted() {
		marks = append(marks, mark{retractedMark, RoleRetracted})
	}
	if mod.IsArchived() {
		marks = append(marks, mark{archivedMark, RoleArchived})
	}
	return marks
}

// markText returns the group as it appears, without colour escapes. It is empty
// when there is nothing to say, so an ordinary module carries no punctuation.
func (mod *Module) markText() string {
	marks := mod.marks()
	if len(marks) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(" (")
	for _, m := range marks {
		b.WriteString(m.letter)
	}
	b.WriteString(")")
	return b.String()
}

// DisplayName returns the name as rendered, without colour escapes.
// Callers measure this to size the name column, since the escapes written by
// FormatName would otherwise be counted as visible characters.
func (mod *Module) DisplayName() string {
	return mod.Name + mod.markText()
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

// FormatName renders the module path, followed by the marks describing the
// module itself: how it is required, and whether it has been given up on.
//
// The marks have to survive shortening, since once a long path is trimmed they
// are part of what distinguishes one module from another. The brackets take the
// name's colour rather than any mark's: they are structure holding the group
// together, not one of the things being said.
func (mod *Module) FormatName(length int) string {
	marks := mod.marks()
	suffix := mod.markText()

	name := shorten(mod.Name, length-len(suffix))
	// Pad outside the colour function: the padding is measured with len, which
	// counts escape bytes, so colouring a padded string misaligns the column.
	pad := max(length-len(name)-len(suffix), 0)

	var out strings.Builder
	out.WriteString(paint(RoleName)(name))
	if len(marks) > 0 {
		structure := paint(RoleName)
		out.WriteString(structure(" ("))
		for _, m := range marks {
			out.WriteString(paint(m.role)(m.letter))
		}
		out.WriteString(structure(")"))
	}
	out.WriteString(strings.Repeat(" ", pad))
	return out.String()
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
// and everything after it, padded to length so that whatever follows aligns.
//
// Reading rightwards from the first change is what shows the scale of the
// upgrade: a new major leaves nothing of the old version intact, while a new
// patch leaves everything before it untouched.
func (mod *Module) FormatTo(length int) string {
	plain, changed := mod.split(mod.To)
	pad := max(length-len(plain)-len(changed), 0)
	return paint(RoleTo)(plain) + paint(mod.changedRole())(changed) + strings.Repeat(" ", pad)
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
