package module

import "time"

// setCooldown puts a period in force, and returns a function restoring the previous
// one. The threshold is package state, so a test that changes it has to put it back.
func setCooldown(d time.Duration) (restore func()) {
	prev := cooldown
	cooldown = d
	return func() { cooldown = prev }
}
