package module

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

// now is what the package reads the time from, so a test can decide what "today"
// is. Nothing else in the codebase asks for the time, which is why the seam is
// here rather than threaded through every caller.
var now = time.Now

// cooldown is how long a release must sit before it is recommended, zero when the
// caller asked for none.
//
// A package-level value rather than a parameter because the predicates a listing
// filters and sorts by receive only a Module, with nowhere to take a threshold. It
// is set once at startup from the flag, as Wide is.
var cooldown time.Duration

// SetCooldown says how long a release must sit before it is recommended. It is
// called once at startup, before anything is listed.
func SetCooldown(d time.Duration) { cooldown = d }

// SetClock decides what the package reads as the current time, returning a function
// restoring the previous one.
//
// Exported because "three days ago" has to mean the same thing on every run, and the
// tests that need to say so are not all in this package.
func SetClock(clock func() time.Time) (restore func()) {
	prev := now
	now = clock
	return func() { now = prev }
}

// Cooldown reports the period in force, for a listing that wants to say what it is.
func Cooldown() time.Duration { return cooldown }

// Age reports how long the version on offer has been published, or zero when the
// date is unknown.
//
// Rounded to the second, since an age is the difference between two instants and
// arrives with nanoseconds on it. Nothing here is decided at that precision, and a
// column showing "46h45m59.033004s" is arithmetic rather than an answer.
//
// Zero rather than the age of the epoch: an unknown date is not an ancient one, and
// reporting a thousand years would read as a settled release.
func (mod *Module) Age() time.Duration {
	if mod.Released.IsZero() {
		return 0
	}
	return now().Sub(mod.Released).Round(time.Second)
}

// releaseFormat is how a publication date is written: a plain calendar day, which is
// what a reader compares against a changelog.
const releaseFormat = "2006-01-02"

// AgeText says how long the version on offer has been published, always relative.
// Empty when the date is unknown, which keeps the column out of a listing that has
// nothing to put in it.
//
// Rounded down to the largest unit that fits, so a release three days and seventeen
// minutes old reads "3d". The remainder is noise in a column a reader scans: what
// matters is whether it has been days or hours, not how many minutes past.
func (mod *Module) AgeText() string {
	if mod.Released.IsZero() {
		return ""
	}
	age := mod.Age()
	for _, at := range rendering {
		u := units[at]
		if age >= u.each {
			return strconv.FormatInt(int64(age/u.each), 10) + u.suffix
		}
	}
	// Under a day, Go's own units are the readable ones; truncate to the largest
	// that fits for the same reason.
	for _, u := range []struct {
		each   time.Duration
		suffix string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if age >= u.each {
			return strconv.FormatInt(int64(age/u.each), 10) + u.suffix
		}
	}
	return FormatDuration(age)
}

// Remaining reports how much longer the version on offer must wait before it is
// recommended, or zero when it is not waiting at all.
func (mod *Module) Remaining() time.Duration {
	if !mod.Cooling() {
		return 0
	}
	return (cooldown - mod.Age()).Round(time.Second)
}

// RemainingText says how much longer the version on offer must wait, empty when it is
// not waiting.
//
// This is what a column headed COOLDOWN answers. The heading names a period, so the
// cell has to be about that period -- an earlier version of this column showed a
// publication date under it, which named one thing and reported another. When the
// version has settled there is nothing being waited for, and an empty cell drops the
// column from a listing that does not need it.
func (mod *Module) RemainingText() string {
	left := mod.Remaining()
	if left <= 0 {
		return ""
	}
	return remaining(left) + " left"
}

// remaining renders how long is left in the largest unit that fits, so a wait of six
// days and a wait of six hours are each stated in the terms a reader acts on.
func remaining(left time.Duration) string {
	for _, at := range rendering {
		u := units[at]
		if left >= u.each {
			return strconv.FormatInt(int64(left/u.each), 10) + u.suffix
		}
	}
	for _, u := range []struct {
		each   time.Duration
		suffix string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if left >= u.each {
			return strconv.FormatInt(int64(left/u.each), 10) + u.suffix
		}
	}
	return FormatDuration(left)
}

// ReleaseText says when the version on offer was published, always absolute.
func (mod *Module) ReleaseText() string {
	if mod.Released.IsZero() {
		return ""
	}
	return mod.Released.Format(releaseFormat)
}

// FormatCooldown renders one of the three date columns, padded to width so what
// follows aligns.
//
// The text is passed in rather than chosen here, since the three differ only in which
// question they answer and share everything about how they look.
func FormatCooldown(text string, width int) string {
	if text == "" {
		return strings.Repeat(" ", max(width, 0))
	}
	return paint(RoleCooldown)(text) + strings.Repeat(" ", max(width-len(text), 0))
}

// Steppable reports whether version is one this module could step back to: strictly
// between what is installed and what is on offer.
//
// It answers before StepBackTo is called, so the ordinary case of a project already
// holding the newest settled version can be told apart from a genuine mistake.
// Otherwise both arrive as the same error, and "up to date with a fast-releasing
// module" gets reported as a failure to do something.
func (mod *Module) Steppable(version string) bool {
	to, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return to.LessThan(mod.To) && to.GreaterThan(mod.From)
}

// StepBackTo offers an earlier version than the newest published, with the date that
// version landed.
//
// A module releasing faster than the cooldown would otherwise never be recommended:
// its newest release is always too fresh, so waiting means waiting forever. Offering
// the newest version that *has* settled keeps the module maintainable without
// recommending anything untested.
//
// Both the version and its date move together. Leaving the date behind would keep the
// module marked as cooling while offering a version that is not, which is the
// contradiction the whole feature exists to avoid.
//
// The version must lie strictly between what is installed and what was offered.
// Anything at or above the offer is not a step back, and anything at or below what is
// installed is a downgrade of work the project has already taken -- in that case
// waiting is the honest answer, and the caller is told so rather than left to notice.
func (mod *Module) StepBackTo(version string, released time.Time) error {
	to, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("stepping back to %q: %w", version, err)
	}
	if !to.LessThan(mod.To) {
		return fmt.Errorf("stepping back to %s: not earlier than the %s already offered",
			to, mod.To)
	}
	if !to.GreaterThan(mod.From) {
		return fmt.Errorf("stepping back to %s: not later than the %s installed",
			to, mod.From)
	}
	mod.To, mod.Released, mod.Newest = to, released, mod.To
	return nil
}

// ChooseVersion offers the version a reader picked, with the date it landed.
//
// Distinct from StepBackTo, which is the tool deciding and may only go earlier than
// what was on offer. A reader shown the cooling releases and their ages may take one,
// including the newest -- having been told what it costs, that is their call.
//
// A version at or below what is installed is still refused: that is a downgrade rather
// than a choice, and nothing in a prompt should be able to ask for one.
func (mod *Module) ChooseVersion(version string, released time.Time) error {
	to, err := semver.NewVersion(version)
	if err != nil {
		return fmt.Errorf("choosing %q: %w", version, err)
	}
	if !to.GreaterThan(mod.From) {
		return fmt.Errorf("choosing %s: not later than the %s installed", to, mod.From)
	}
	// Newest is left as it was: whether the choice passed something over is decided
	// by comparing the two, so choosing the newest clears the mark by itself.
	mod.To, mod.Released = to, released
	return nil
}

// Cooling reports whether the version on offer is too fresh to recommend.
//
// A release published hours ago has had no time to be found broken, so it is
// withheld until it has settled. Two things are deliberately not cooling:
//
// A version whose date is unknown, since treating zero as "just published" would
// withhold every module the toolchain said nothing about.
//
// A module whose advisories the code reaches, since waiting keeps the vulnerability
// while the upgrade is what resolves it. An advisory merely present in a dependency
// is not enough: nothing is calling the vulnerable code, so there is no hurry.
func (mod *Module) Cooling() bool {
	if cooldown <= 0 || mod.Released.IsZero() {
		return false
	}
	if mod.VulnCalled() {
		return false
	}
	return mod.Age() < cooldown
}
