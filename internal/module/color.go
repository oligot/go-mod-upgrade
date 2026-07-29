package module

import (
	"fmt"
	"slices"
	"strings"

	"github.com/fatih/color"
)

// The roles a colour can be given. Each names one part of a listed module, so
// that what a colour means is decided by where it appears rather than by the
// colour itself.
const (
	// RoleName is the module path.
	RoleName = "name"
	// RoleIndirect is the marker distinguishing an indirect requirement.
	RoleIndirect = "indirect"
	// RoleFrom and RoleTo colour the part of each version that does not
	// change. The part that does is coloured by which component moved, the
	// same in both, so the change reads as one thing seen twice.
	RoleFrom = "from"
	RoleTo   = "to"
	// RoleToMajor, RoleToMinor, RoleToMicro and RoleToPrerelease colour the
	// part of the new version that changes, and everything after it. Which one
	// applies is decided by the leftmost component that moves.
	RoleToMajor      = "to-major"
	RoleToMinor      = "to-minor"
	RoleToMicro      = "to-micro"
	RoleToPrerelease = "to-prerelease"
	// RoleCVE is an advisory the code does not reach, RoleCVEReachable one it
	// does.
	RoleCVE          = "cve"
	RoleCVEReachable = "cve-reachable"
	// RoleDeprecated, RoleRetracted and RoleArchived mark a module that has been
	// given up on. They colour a letter beside the name rather than a column of
	// their own, since they describe the module rather than the step between two
	// versions.
	RoleDeprecated = "deprecated"
	RoleRetracted  = "retracted"
	RoleArchived   = "archived"
	// RoleTransitive marks a module another upgrade would resolve, so it recedes
	// rather than competing with the rows that need acting on.
	RoleTransitive = "transitive"
	// RoleFixes marks an upgrade that would resolve an advisory elsewhere, which
	// is the most useful thing a row can say.
	RoleFixes = "fixes"
	// RoleRequiredBy names what pulls the module in.
	RoleRequiredBy = "required-by"
)

// ColorsEnv names the variable carrying a user's palette.
const ColorsEnv = "GO_MOD_UPGRADE_COLORS"

// palette holds the attributes chosen for each role.
type palette map[string][]color.Attribute

// defaults are chosen from the eight base colours and the bold and faint
// attributes, which a terminal maps to its own theme. A fixed shade would
// read well against one background and badly against the other, and both
// light and dark terminals are common.
var defaults = palette{
	// The name carries no colour of its own: it is the one column always
	// present, and colouring it would compete with the columns that mean
	// something.
	RoleName:     nil,
	RoleIndirect: {color.Faint},
	// Neither version is news in itself, so both recede. The one being left
	// behind recedes further, which is what tells the columns apart once they
	// share a colour for the part that changes.
	RoleFrom: {color.Faint},
	RoleTo:   {color.FgHiBlack},
	// The new version is coloured by how much of it moves.
	RoleToMajor:      {color.FgRed},
	RoleToMinor:      {color.FgYellow},
	RoleToMicro:      {color.FgGreen},
	RoleToPrerelease: {color.FgMagenta},
	// An advisory is the most pressing thing on a row, and one the code
	// reaches more pressing still.
	RoleCVE:          {color.FgYellow},
	RoleCVEReachable: {color.Bold, color.FgRed},
	// Being given up on is a standing condition rather than news, so these
	// recede beside an advisory. A withdrawn version is the sharpest of the
	// three, being the one upstream says not to use at all.
	RoleDeprecated: {color.FgYellow},
	RoleRetracted:  {color.Bold, color.FgYellow},
	RoleArchived:   {color.FgYellow},
	// Nothing has to be done about a transitively resolved module, so it is the
	// one mark that recedes. An upgrade that clears an advisory elsewhere is the
	// opposite: the one row worth acting on first.
	RoleTransitive: {color.Faint},
	RoleFixes:      {color.Bold, color.FgGreen},
	RoleRequiredBy: {color.Faint},
}

// attributes maps the names accepted in a palette to their attributes.
var attributes = map[string]color.Attribute{
	"none":      color.Reset,
	"bold":      color.Bold,
	"faint":     color.Faint,
	"italic":    color.Italic,
	"underline": color.Underline,
	"black":     color.FgBlack,
	"red":       color.FgRed,
	"green":     color.FgGreen,
	"yellow":    color.FgYellow,
	"blue":      color.FgBlue,
	"magenta":   color.FgMagenta,
	"cyan":      color.FgCyan,
	"white":     color.FgWhite,
}

// active is the palette in use. It is replaced once at startup.
var active = defaults

// The named palettes, which stand in for spelling out every role.
const (
	// SchemeDark suits a dark background and is what the defaults assume.
	SchemeDark = "dark"
	// SchemeLight suits a light background, where the faint attribute and the
	// brighter colours wash out.
	SchemeLight = "light"
)

// schemes holds the palettes that can be named instead of listed.
//
// There is no dependable way to ask a terminal what its background is, so dark
// is assumed and light has to be asked for.
var schemes = map[string]palette{
	SchemeDark: defaults,
	SchemeLight: {
		RoleName:     nil,
		RoleIndirect: {color.FgHiBlack},
		// Faint is close to invisible on a light background, so the receding
		// columns take the dimmest colour that still has contrast.
		RoleFrom: {color.Faint},
		RoleTo:   {color.FgHiBlack},
		// Yellow and green on white are hard to read, so the version colours
		// move to their darker neighbours.
		RoleToMajor:      {color.FgRed},
		RoleToMinor:      {color.FgMagenta},
		RoleToMicro:      {color.FgBlue},
		RoleToPrerelease: {color.FgCyan},
		RoleCVE:          {color.FgMagenta},
		RoleCVEReachable: {color.Bold, color.FgRed},
		RoleDeprecated:   {color.FgMagenta},
		RoleRetracted:    {color.Bold, color.FgMagenta},
		RoleArchived:     {color.FgMagenta},
		RoleTransitive:   {color.FgHiBlack},
		RoleFixes:        {color.Bold, color.FgGreen},
		RoleRequiredBy:   {color.FgHiBlack},
	},
}

// SchemeNames lists the palettes that can be named.
func SchemeNames() []string {
	return []string{SchemeDark, SchemeLight}
}

// Roles lists the roles a palette may set, in the order they appear in a row.
func Roles() []string {
	return []string{
		RoleName, RoleFixes, RoleIndirect, RoleTransitive,
		RoleDeprecated, RoleRetracted, RoleArchived,
		RoleFrom, RoleTo,
		RoleToMajor, RoleToMinor, RoleToMicro, RoleToPrerelease,
		RoleCVE, RoleCVEReachable, RoleRequiredBy,
	}
}

// Attributes lists the attribute names a palette may use.
func Attributes() []string {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// SetColors replaces the roles named in spec, leaving the rest at their
// defaults. The spec is a comma-separated list of role=attributes, with the
// attributes joined by "+", as in "cve=bold+red,from=faint".
//
// A palette may also be named, as in "light" or "light,cve=magenta", which
// starts from that palette instead of the default one.
func SetColors(spec string) error {
	base := schemes[SchemeDark]
	fields := strings.Split(spec, ",")

	// A leading name chooses the palette the rest of the spec adjusts.
	if len(fields) > 0 {
		if name := strings.ToLower(strings.TrimSpace(fields[0])); !strings.Contains(name, "=") {
			if name != "" {
				scheme, ok := schemes[name]
				if !ok {
					return fmt.Errorf("unknown colour scheme %q, expected one of: %s",
						name, strings.Join(SchemeNames(), ", "))
				}
				base = scheme
			}
			fields = fields[1:]
		}
	}

	p := palette{}
	for role, attrs := range base {
		p[role] = attrs
	}

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		role, list, ok := strings.Cut(field, "=")
		if !ok {
			return fmt.Errorf("colour %q is not role=attributes", field)
		}
		role = strings.ToLower(strings.TrimSpace(role))
		if _, known := defaults[role]; !known {
			return fmt.Errorf("unknown colour role %q, expected one of: %s",
				role, strings.Join(Roles(), ", "))
		}

		var attrs []color.Attribute
		for _, name := range strings.Split(list, "+") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			attr, known := attributes[name]
			if !known {
				return fmt.Errorf("unknown colour %q for role %q, expected one of: %s",
					name, role, strings.Join(Attributes(), ", "))
			}
			// "none" leaves the role uncoloured, so it cannot be combined.
			if attr == color.Reset {
				attrs = nil
				break
			}
			attrs = append(attrs, attr)
		}
		p[role] = attrs
	}
	active = p
	return nil
}

// paint returns the function rendering text in the colour for a role.
func paint(role string) func(a ...any) string {
	attrs := active[role]
	if len(attrs) == 0 {
		// Returning the text unchanged keeps a role that is deliberately
		// uncoloured from emitting a reset sequence.
		return func(a ...any) string { return fmt.Sprint(a...) }
	}
	return color.New(attrs...).SprintFunc()
}
