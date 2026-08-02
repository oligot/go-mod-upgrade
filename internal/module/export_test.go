package module

import "time"

// setClock makes the package read the time from clock, and returns a function
// restoring what it read before.
//
// "Three days ago" has to mean the same thing on every run, so a test decides what
// today is rather than asking the machine.
func setClock(clock func() time.Time) (restore func()) {
	prev := now
	now = clock
	return func() { now = prev }
}

// setCooldown puts a period in force, and returns a function restoring the previous
// one. The threshold is package state, so a test that changes it has to put it back.
func setCooldown(d time.Duration) (restore func()) {
	prev := cooldown
	cooldown = d
	return func() { cooldown = prev }
}
