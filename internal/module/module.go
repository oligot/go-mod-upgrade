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

// nameColor picks the colour that conveys how large the update is.
func (mod *Module) nameColor() func(a ...any) string {
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
	c := mod.nameColor()
	if !mod.Indirect {
		return c(padRight(mod.Name, length))
	}
	// Pad outside the colour functions: padRight measures with len, which
	// counts escape bytes, so colouring a padded string misaligns the column.
	faint := color.New(color.Faint).SprintFunc()
	pad := max(length-len(mod.DisplayName()), 0)
	return c(mod.Name) + faint(indirectMarker) + strings.Repeat(" ", pad)
}

func (mod *Module) FormatFrom(length int) string {
	c := color.New(color.FgBlue).SprintFunc()
	return c(padRight(mod.From.String(), length))
}

func (mod *Module) FormatTo() string {
	green := color.New(color.FgGreen).SprintFunc()
	var buf bytes.Buffer
	from := mod.From
	to := mod.To
	same := true
	fmt.Fprintf(&buf, "%d.", to.Major())
	if from.Minor() == to.Minor() {
		fmt.Fprintf(&buf, "%d.", to.Minor())
	} else {
		fmt.Fprintf(&buf, "%s%s", green(to.Minor()), green("."))
		same = false
	}
	if from.Patch() == to.Patch() && same {
		fmt.Fprintf(&buf, "%d", to.Patch())
	} else {
		fmt.Fprintf(&buf, "%s", green(to.Patch()))
		same = false
	}
	if to.Prerelease() != "" {
		if from.Prerelease() == to.Prerelease() && same {
			fmt.Fprintf(&buf, "-%s", to.Prerelease())
		} else {
			fmt.Fprintf(&buf, "-%s", green(to.Prerelease()))
		}
	}
	if to.Metadata() != "" {
		fmt.Fprintf(&buf, "%s%s", green("+"), green(to.Metadata()))
	}
	return buf.String()
}
