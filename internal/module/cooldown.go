package module

import "time"

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

// Cooldown reports the period in force, for a listing that wants to say what it is.
func Cooldown() time.Duration { return cooldown }

// Age reports how long the version on offer has been published, or zero when the
// date is unknown.
//
// Zero rather than the age of the epoch: an unknown date is not an ancient one, and
// reporting a thousand years would read as a settled release.
func (mod *Module) Age() time.Duration {
	if mod.Released.IsZero() {
		return 0
	}
	return now().Sub(mod.Released)
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
