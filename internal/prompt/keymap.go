package prompt

import (
	"charm.land/bubbles/v2/key"
	"charm.land/huh/v2"
)

const (
	// selectAllKey toggles every module on or off, the key npm-check-updates
	// uses for the same thing. The press is relayed by [selector], not bound
	// here: huh matches its select-all binding even while the filter is open,
	// so a bare letter bound here could never be typed into the filter.
	selectAllKey = "a"

	// selectAllRelayKey is what the binding below actually listens on, and so
	// what [selector] forwards in place of selectAllKey.
	//
	// It doubles as a chord for the same action, which is why it is a real key
	// and not an unprintable one. huh defaults it to ctrl+a, unusable under
	// the widespread tmux configuration that rebinds the prefix from ctrl+b to
	// ctrl+a: tmux eats the keystroke, and the doubled ctrl+a ctrl+a needed to
	// pass one through is not something a prompt should ask for.
	selectAllRelayKey = "ctrl+t"
)

// keymap returns huh's default bindings with select-all moved off ctrl+a.
//
// SelectAll and SelectNone deliberately stay on one key: huh matches both in
// the same branch and enables whichever one describes the next press, so the
// pair is a single toggle whose help text flips.
func keymap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.MultiSelect.SelectAll = key.NewBinding(
		key.WithKeys(selectAllRelayKey),
		key.WithHelp(selectAllKey, "select all"),
	)
	km.MultiSelect.SelectNone = key.NewBinding(
		key.WithKeys(selectAllRelayKey),
		key.WithHelp(selectAllKey, "select none"),
		key.WithDisabled(),
	)
	return km
}
