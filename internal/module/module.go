package module

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
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
	// VulnCalled reports whether any of those advisories covers code this
	// module's dependants actually reach.
	VulnCalled bool
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

// upgradeColor picks the colour conveying how disruptive the upgrade is. It
// belongs to the version columns, which are what actually change; the name is
// left plain so that the colour beside a module means one thing only.
func (mod *Module) upgradeColor() func(a ...any) string {
	from := mod.From
	to := mod.To
	switch {
	case from.Major() == 0:
		return color.New(color.FgRed).SprintFunc()
	case from.Minor() < to.Minor():
		return color.New(color.FgYellow).SprintFunc()
	case from.Patch() < to.Patch():
		return color.New(color.FgGreen).SprintFunc()
	default:
		return color.New(color.FgWhite).SprintFunc()
	}
}

func (mod *Module) FormatName(length int) string {
	name := mod.Name
	if !mod.Indirect {
		return padRight(shorten(name, length), length)
	}
	// The marker has to survive shortening, since it is what distinguishes an
	// indirect requirement from a direct one.
	name = shorten(name, length-len(indirectMarker))
	// Pad outside the colour function: padRight measures with len, which
	// counts escape bytes, so colouring a padded string misaligns the column.
	faint := color.New(color.Faint).SprintFunc()
	pad := max(length-len(name)-len(indirectMarker), 0)
	return name + faint(indirectMarker) + strings.Repeat(" ", pad)
}

// FormatRequiredBy renders what pulls the module in, shortened to fit within
// width columns. Entries are dropped from the end, where the ordering has put
// the least informative ones, and replaced by a count of what was left out.
func (mod *Module) FormatRequiredBy(width int) string {
	if len(mod.RequiredBy) == 0 {
		return ""
	}
	faint := color.New(color.Faint).SprintFunc()

	// Try the whole list, then progressively fewer entries, and keep the
	// longest rendering that fits.
	for shown := len(mod.RequiredBy); shown > 0; shown-- {
		text := strings.Join(mod.RequiredBy[:shown], ", ")
		if left := len(mod.RequiredBy) - shown; left > 0 {
			text += fmt.Sprintf(" +%d more", left)
		}
		if len(text) <= width || shown == 1 {
			return faint(text)
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
	c := color.New(color.FgYellow).SprintFunc()
	if mod.VulnCalled {
		c = color.New(color.FgRed).SprintFunc()
	}
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

func (mod *Module) FormatFrom(length int) string {
	c := color.New(color.FgBlue).SprintFunc()
	return c(padRight(mod.From.String(), length))
}

func (mod *Module) FormatTo() string {
	// The parts that change are highlighted in the colour conveying how
	// disruptive the change is, so the magnitude reads from the version itself.
	changed := mod.upgradeColor()
	var buf bytes.Buffer
	from := mod.From
	to := mod.To
	same := true
	fmt.Fprintf(&buf, "%d.", to.Major())
	if from.Minor() == to.Minor() {
		fmt.Fprintf(&buf, "%d.", to.Minor())
	} else {
		fmt.Fprintf(&buf, "%s%s", changed(to.Minor()), changed("."))
		same = false
	}
	if from.Patch() == to.Patch() && same {
		fmt.Fprintf(&buf, "%d", to.Patch())
	} else {
		fmt.Fprintf(&buf, "%s", changed(to.Patch()))
		same = false
	}
	if to.Prerelease() != "" {
		if from.Prerelease() == to.Prerelease() && same {
			fmt.Fprintf(&buf, "-%s", to.Prerelease())
		} else {
			fmt.Fprintf(&buf, "-%s", changed(to.Prerelease()))
		}
	}
	if to.Metadata() != "" {
		fmt.Fprintf(&buf, "%s%s", changed("+"), changed(to.Metadata()))
	}
	return buf.String()
}
