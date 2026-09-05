// Package cooldown withholds module versions that were published too recently.
package cooldown

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/oligot/go-mod-upgrade/internal/module"
)

// ParseDuration parses a cooldown period. A bare number is a number of days; a
// number may also carry a d, h or m suffix.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty cooldown period")
	}
	digits := s
	unit := 24 * time.Hour
	switch s[len(s)-1] {
	case 'd':
		digits = s[:len(s)-1]
	case 'h':
		digits = s[:len(s)-1]
		unit = time.Hour
	case 'm':
		digits = s[:len(s)-1]
		unit = time.Minute
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("invalid cooldown period %q: expected a number of days or a value like 7d, 12h or 30m", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid cooldown period %q: must not be negative", s)
	}
	return time.Duration(n) * unit, nil
}

// VersionInfo is a candidate module version and the time it was published.
type VersionInfo struct {
	Version *semver.Version
	Time    time.Time
}

// Lookup reports the tagged versions of a module newer than after, in ascending
// order, together with their publish times.
type Lookup func(name string, after *semver.Version) ([]VersionInfo, error)

// Held is a module whose update was withheld entirely by the cooldown window.
type Held struct {
	Name    string
	Version *semver.Version
	Age     time.Duration
}

// Filter applies the cooldown window to mods. A module whose target version is
// too recent falls back to the greatest version old enough to satisfy the
// window. Modules with no such version, and modules whose versions can't be
// checked, are removed from the returned modules and reported as held back.
func Filter(mods []module.Module, window time.Duration, now time.Time, lookup Lookup) ([]module.Module, []Held) {
	if window <= 0 {
		return mods, nil
	}
	kept := []module.Module{}
	held := []Held{}
	for _, mod := range mods {
		// go list omits the publish time when it can't determine it, leaving
		// ToTime at the zero value. Subtracting it would yield an age of two
		// millennia and wave the version through unverified, so treat an unknown
		// time as an age of zero and let the lookup path decide: fail closed.
		known := !mod.ToTime.IsZero()
		var age time.Duration
		if known {
			age = now.Sub(mod.ToTime)
		}
		if known && age >= window {
			kept = append(kept, mod)
			continue
		}
		log.WithFields(log.Fields{
			"name":    mod.Name,
			"version": mod.To.String(),
			"age":     age,
			"window":  window,
		}).Debug("Version is within the cooldown window")
		candidates, err := lookup(mod.Name, mod.From)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  mod.Name,
			}).Warn("Couldn't check versions, holding module back")
			held = append(held, Held{Name: mod.Name, Version: mod.To, Age: age})
			continue
		}
		fallback, ok := greatestOldEnough(mod, candidates, window, now)
		if !ok {
			log.WithFields(log.Fields{
				"name": mod.Name,
			}).Debug("No version satisfies the cooldown window, holding module back")
			held = append(held, Held{Name: mod.Name, Version: mod.To, Age: age})
			continue
		}
		log.WithFields(log.Fields{
			"name": mod.Name,
			"held": mod.To.String(),
			"use":  fallback.Version.String(),
		}).Debug("Falling back to an earlier version")
		mod.Cooldown = &module.Cooldown{Version: mod.To, Age: age}
		mod.To = fallback.Version
		mod.ToTime = fallback.Time
		kept = append(kept, mod)
	}
	return kept, held
}

// greatestOldEnough returns the highest candidate that is an upgrade for mod,
// lower than its current target, and published at least window ago.
func greatestOldEnough(mod module.Module, candidates []VersionInfo, window time.Duration, now time.Time) (VersionInfo, bool) {
	for i := len(candidates) - 1; i >= 0; i-- {
		candidate := candidates[i]
		if !candidate.Version.GreaterThan(mod.From) || !candidate.Version.LessThan(mod.To) {
			continue
		}
		// go list -m -versions does list prerelease tags, and semver orders
		// v1.4.0-rc.1 below v1.4.0. Offering one to a user on a stable version
		// would introduce an upgrade go list -u would never propose, so only stay
		// on a prerelease line the module is already on.
		if candidate.Version.Prerelease() != "" && mod.From.Prerelease() == "" {
			log.WithFields(log.Fields{
				"name":    mod.Name,
				"version": candidate.Version.String(),
			}).Debug("Skipping prerelease version")
			continue
		}
		if candidate.Time.IsZero() {
			log.WithFields(log.Fields{
				"name":    mod.Name,
				"version": candidate.Version.String(),
			}).Debug("No publish time for version, skipping")
			continue
		}
		if now.Sub(candidate.Time) >= window {
			return candidate, true
		}
	}
	return VersionInfo{}, false
}
