package module

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	gomod "golang.org/x/mod/module"
)

// The labels a module can carry. Each says something about the module itself
// rather than about the step between two versions, which is what the rest of a
// row is about -- together they answer why a row is where it is.
//
// Each is a single letter so several fit in one narrow column: a module can be
// required indirectly, deprecated by its author, and marked archived by a
// reviewer all at once, reading as "iDA". Their order mirrors the default sort,
// so the labels read as the priority the listing is ordered by.
const (
	// fixLabel is an upgrade that would resolve an advisory in another module.
	fixLabel = "F"
	// indirectLabel distinguishes a requirement reached only through another
	// module from one the code imports directly.
	indirectLabel = "i"
	// transitiveLabel is a module whose advisories another upgrade would resolve,
	// so it needs no direct action.
	transitiveLabel = "T"
	// deprecatedLabel is the author deprecating the module.
	deprecatedLabel = "D"
	// retractedLabel is the author withdrawing the version in use.
	retractedLabel = "R"
	// archivedLabel is a policy asserting the module is abandoned.
	archivedLabel = "A"
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
	// FixedBy names the modules whose own upgrade would lift this one past the
	// version fixing its advisories, empty when none would.
	//
	// Go selects the highest version any module asks for, so upgrading a
	// dependent that already requires the fixed version resolves the advisory
	// without this module being named at all. Such a module needs no direct
	// action, which is why it sorts last.
	FixedBy []string
	// Fixes names the modules whose advisories this module's own upgrade would
	// resolve, the inverse of FixedBy. Taking such an upgrade clears an advisory
	// somewhere else, which makes it the most useful row in a listing.
	Fixes []string
	// Tags names the build configurations that reach this module, empty when
	// every configuration does.
	//
	// A build tag decides which files compile, so a module reached only under one
	// configuration is one a plain build never sees. Saying which configurations
	// reach it is what distinguishes a dependency of the tests from one of the
	// program.
	Tags []string
	// Released is when the version on offer was published, or when the version in
	// use was if there is nothing newer.
	//
	// A release published hours ago has had no time to be found broken, which is
	// what the cooldown weighs. Zero means the toolchain did not say, which reads
	// as unknown rather than as fresh.
	Released time.Time
}

// IsFix reports whether upgrading this module would resolve an advisory in
// another, which is worth doing beyond the upgrade's own merits.
func (mod *Module) IsFix() bool { return len(mod.Fixes) > 0 }

// IsDeprecated reports whether the author has deprecated the module.
func (mod *Module) IsDeprecated() bool { return mod.Deprecated != "" }

// IsRetracted reports whether the author has withdrawn the version in use.
func (mod *Module) IsRetracted() bool { return len(mod.Retracted) > 0 }

// IsArchived reports whether a policy asserts the module is abandoned.
func (mod *Module) IsArchived() bool { return mod.Archived != "" }

// IsTransitive reports whether another upgrade would resolve this module's
// advisories, so it needs no direct action.
func (mod *Module) IsTransitive() bool { return len(mod.FixedBy) > 0 }

// Disowned reports whether the module has been given up on, by its author or by
// a reviewer. Such a module is worth attention whatever its version says.
func (mod *Module) Disowned() bool {
	return mod.IsDeprecated() || mod.IsRetracted() || mod.IsArchived()
}

// VulnCalled reports whether any advisory covers code that is reached.
func (mod *Module) VulnCalled() bool {
	return mod.Reachable > 0
}

// label is one letter of the label column, and the role colouring it.
type label struct {
	letter string
	role   string
}

// labels returns the labels the module carries, in the order they are rendered.
//
// The order mirrors DefaultSort, so the labels read as the same priority the
// listing is ordered by: an upgrade that fixes something elsewhere first, then
// how the module is required, then whether another upgrade already handles it.
// The disowned labels come last, having no key in the default chain.
//
// Reading a row and reading the listing therefore agree: a leading "F" is the
// same statement as sitting at the top.
func (mod *Module) labels() []label {
	var labels []label
	if mod.IsFix() {
		labels = append(labels, label{fixLabel, RoleFixes})
	}
	if mod.Indirect {
		labels = append(labels, label{indirectLabel, RoleIndirect})
	}
	if mod.IsTransitive() {
		labels = append(labels, label{transitiveLabel, RoleTransitive})
	}
	if mod.IsDeprecated() {
		labels = append(labels, label{deprecatedLabel, RoleDeprecated})
	}
	if mod.IsRetracted() {
		labels = append(labels, label{retractedLabel, RoleRetracted})
	}
	if mod.IsArchived() {
		labels = append(labels, label{archivedLabel, RoleArchived})
	}
	return labels
}

// LabelText returns the labels as they appear, without colour escapes, which is
// what a caller measures to size the column. It is empty when the module carries
// none, which is what keeps the column out of a listing that needs no labels.
func (mod *Module) LabelText() string {
	var b strings.Builder
	for _, l := range mod.labels() {
		b.WriteString(l.letter)
	}
	return b.String()
}

// FormatLabels renders the labels, padded to width so what follows aligns. Each
// letter takes its own colour, since each says a different thing.
func (mod *Module) FormatLabels(width int) string {
	labels := mod.labels()
	if len(labels) == 0 {
		return strings.Repeat(" ", max(width, 0))
	}
	var b strings.Builder
	for _, l := range labels {
		b.WriteString(paint(l.role)(l.letter))
	}
	b.WriteString(strings.Repeat(" ", max(width-len(labels), 0)))
	return b.String()
}

// DisplayName returns the name as rendered, without colour escapes.
// Callers measure this to size the name column, since the escapes written by
// FormatName would otherwise be counted as visible characters.
func (mod *Module) DisplayName() string { return mod.Name }

// FormatName renders the module path, padded to length so that what follows
// aligns. A path too long for the column is trimmed at the front, since the
// trailing segments identify it better than the host does.
func (mod *Module) FormatName(length int) string {
	name := shorten(mod.Name, length)
	// Pad outside the colour function: the padding is measured with len, which
	// counts escape bytes, so colouring a padded string misaligns the column.
	return paint(RoleName)(name) + strings.Repeat(" ", max(length-len(name), 0))
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

// FormatHint renders what taking this upgrade would resolve elsewhere, or what
// would resolve this module without upgrading it, shortened to fit width.
//
// The two are the same relation seen from either end, so they share a column:
// a row either offers to fix something or says something else will fix it, never
// both. Fixing takes precedence in the unlikely case both apply, since acting is
// more useful to know than not having to.
func (mod *Module) FormatHint(width int) string {
	switch {
	case mod.IsFix():
		return hint(RoleFixes, "fixes ", mod.Fixes, width)
	case mod.IsTransitive():
		return hint(RoleTransitive, "fixed by ", mod.FixedBy, width)
	default:
		return ""
	}
}

// hint renders a labelled list of module paths, dropping entries from the end
// until it fits and replacing them with a count.
func hint(role, label string, paths []string, width int) string {
	c := paint(role)
	for shown := len(paths); shown > 0; shown-- {
		text := label + strings.Join(paths[:shown], ", ")
		if left := len(paths) - shown; left > 0 {
			text += fmt.Sprintf(" +%d more", left)
		}
		if len(text) <= width || shown == 1 {
			return c(text)
		}
	}
	return ""
}

// HintText returns the hint without colour escapes, which is what a caller
// measures to size the column.
func (mod *Module) HintText() string {
	var label string
	var paths []string
	switch {
	case mod.IsFix():
		label, paths = "fixes ", mod.Fixes
	case mod.IsTransitive():
		label, paths = "fixed by ", mod.FixedBy
	default:
		return ""
	}
	return label + strings.Join(paths, ", ")
}

// JoinPaths writes a list of module paths separated by single spaces.
//
// A path holding a space or a quote would run into its neighbour, so such a path
// is quoted. The quotes are left off otherwise, since a path never needs them and
// they would only cost width in a column that has little to spare.
func JoinPaths(paths []string) string {
	var b strings.Builder
	for i, path := range paths {
		if i > 0 {
			b.WriteString(" ")
		}
		if quoted := strconv.Quote(path); quoted != `"`+path+`"` || strings.ContainsAny(path, " \t") {
			b.WriteString(quoted)
			continue
		}
		b.WriteString(path)
	}
	return b.String()
}

// FormatTags renders the build configurations reaching the module, padded to
// width. It is empty when every configuration reaches it, which keeps the column
// out of a listing where it would say the same thing on every row.
func (mod *Module) FormatTags(width int) string {
	if len(mod.Tags) == 0 {
		return strings.Repeat(" ", max(width, 0))
	}
	text := JoinPaths(mod.Tags)
	return paint(RoleTags)(text) + strings.Repeat(" ", max(width-len(text), 0))
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
	// longest rendering that fits. The entries are separated by a space rather
	// than a comma: a module path cannot contain one, so the comma is punctuation
	// that only costs width.
	for shown := len(mod.RequiredBy); shown > 0; shown-- {
		text := JoinPaths(mod.RequiredBy[:shown])
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

// Wide reports whether versions are rendered in full. It is set once at startup
// from --width, since a caller asking for room enough to see everything wants the
// versions unabbreviated too.
var Wide bool

// revision returns the commit a pseudo-version names, empty when the version is
// not one.
//
// Go writes a dependency pinned to a commit as "v0.0.0-20260708182218-49f421fb7959":
// a base version, a timestamp, and the revision. Only the revision identifies it
// -- the base is usually v0.0.0 and the timestamp is implied by the commit -- so a
// listing shows that alone unless asked for the whole thing.
func revision(v *semver.Version) string {
	if !gomod.IsPseudoVersion("v" + v.String()) {
		return ""
	}
	rev, err := gomod.PseudoVersionRev("v" + v.String())
	if err != nil {
		return ""
	}
	return rev
}

// VersionText returns a version as a listing shows it, which is what a caller
// measures to size the column.
func VersionText(v *semver.Version) string {
	if !Wide {
		if rev := revision(v); rev != "" {
			return rev
		}
	}
	return v.String()
}

// FormatFrom renders the current version, highlighting the part the upgrade
// replaces in the same colour the new version uses for it.
//
// The two columns share that colour so the change reads as one thing seen
// twice; what distinguishes them is the unchanged prefix, which recedes
// further in the version being left behind.
func (mod *Module) FormatFrom(length int) string {
	if rev := shortened(mod.From); rev != "" {
		return paint(mod.changedRole())(rev) + strings.Repeat(" ", max(length-len(rev), 0))
	}
	plain, changed := mod.split(mod.From)
	pad := max(length-len(plain)-len(changed), 0)
	return paint(RoleFrom)(plain) + paint(mod.changedRole())(changed) + strings.Repeat(" ", pad)
}

// shortened returns the abbreviated form of a version, empty when it is shown in
// full.
//
// A pseudo-version has no meaningful parts to compare, so the whole of it takes
// the colour saying how disruptive the change is rather than being split.
func shortened(v *semver.Version) string {
	if Wide {
		return ""
	}
	return revision(v)
}

// FormatTo renders the new version, colouring the leftmost part that changes
// and everything after it, padded to length so that whatever follows aligns.
//
// Reading rightwards from the first change is what shows the scale of the
// upgrade: a new major leaves nothing of the old version intact, while a new
// patch leaves everything before it untouched.
func (mod *Module) FormatTo(length int) string {
	if rev := shortened(mod.To); rev != "" {
		return paint(mod.changedRole())(rev) + strings.Repeat(" ", max(length-len(rev), 0))
	}
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
