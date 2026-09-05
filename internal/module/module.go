package module

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
)

func padRight(str string, length int) string {
	if len(str) >= length {
		return str
	}
	return str + strings.Repeat(" ", length-len(str))
}

// Cooldown records the version that the cooldown window withheld.
type Cooldown struct {
	Version *semver.Version
	Age     time.Duration
}

type Module struct {
	Name string
	From *semver.Version
	To   *semver.Version
	// ToTime is the publish time of the To version.
	ToTime time.Time
	// Cooldown is set only when the cooldown window lowered the To version.
	Cooldown *Cooldown
}

// MaxWidths returns the width of the longest module name and of the longest
// current version, for padding the columns the formatters produce.
func MaxWidths(modules []Module) (name, from int) {
	for _, mod := range modules {
		name = max(name, len(mod.Name))
		from = max(from, len(mod.From.String()))
	}
	return name, from
}

func (mod *Module) FormatName(length int) string {
	c := color.New(color.FgWhite).SprintFunc()
	from := mod.From
	to := mod.To
	if from.Major() == 0 {
		c = color.New(color.FgRed).SprintFunc()
	} else if from.Minor() < to.Minor() {
		c = color.New(color.FgYellow).SprintFunc()
	} else if from.Patch() < to.Patch() {
		c = color.New(color.FgGreen).SprintFunc()
	}
	return c(padRight(mod.Name, length))
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

// FormatAge renders a duration coarsely, as minutes, hours or days.
func FormatAge(d time.Duration) string {
	// A tag dated in the future, through clock skew or backdating, would
	// otherwise render as a negative age.
	if d < 0 {
		d = 0
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}

// FormatCooldown renders the annotation for a module whose target version was
// lowered by the cooldown window, or an empty string when it was not.
func (mod *Module) FormatCooldown() string {
	if mod.Cooldown == nil {
		return ""
	}
	c := color.New(color.Faint).SprintFunc()
	return c(fmt.Sprintf(" (%s held, %s old)", mod.Cooldown.Version, FormatAge(mod.Cooldown.Age)))
}
