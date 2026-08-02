package module

import (
	"strconv"
	"strings"
	"time"
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

// ReleaseText says when the version on offer was published, always absolute.
func (mod *Module) ReleaseText() string {
	if mod.Released.IsZero() {
		return ""
	}
	return mod.Released.Format(releaseFormat)
}

// CooldownText says how long a version has been out while it is still settling, and
// the date it landed once it has.
//
// The two answer different questions and only one is worth asking at a time. While a
// release is cooling, how much longer it needs is what a reader wants, and an age
// gives it. Once settled the age only climbs and says nothing, so the date takes over
// -- a fixed value that reads the same on every run.
func (mod *Module) CooldownText() string {
	if mod.Released.IsZero() {
		return ""
	}
	if mod.Cooling() {
		return mod.AgeText()
	}
	return mod.ReleaseText()
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
