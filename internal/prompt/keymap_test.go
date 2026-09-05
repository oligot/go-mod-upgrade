package prompt

import (
	"slices"
	"testing"
)

// ctrl+a is the tmux prefix in a common configuration, so tmux swallows it
// before huh ever sees it. Assert the rebind rather than the absence only, so a
// huh upgrade that renames or re-defaults the binding fails loudly here.
func TestKeyMapAvoidsTmuxPrefix(t *testing.T) {
	multiSelect := keymap().MultiSelect
	cases := map[string][]string{
		"SelectAll":  multiSelect.SelectAll.Keys(),
		"SelectNone": multiSelect.SelectNone.Keys(),
	}
	for what, keys := range cases {
		if slices.Contains(keys, "ctrl+a") {
			t.Errorf("%s is bound to ctrl+a (%v), which tmux captures as its prefix", what, keys)
		}
		if !slices.Contains(keys, selectAllRelayKey) {
			t.Errorf("%s is bound to %v, want it to include %q", what, keys, selectAllRelayKey)
		}
	}
}

// huh matches both bindings in the same case and only uses the enabled one for
// the help line, so they have to stay on one key to keep toggling.
func TestKeyMapSelectAllAndNoneShareAKey(t *testing.T) {
	multiSelect := keymap().MultiSelect
	all, none := multiSelect.SelectAll.Keys(), multiSelect.SelectNone.Keys()
	if !slices.Equal(all, none) {
		t.Errorf("SelectAll is bound to %v and SelectNone to %v, want the same key", all, none)
	}
}

// The help line has to name the relayed key, not the one huh listens on: the
// letter is what users are told to press, and what [selector] translates.
func TestKeyMapHelpNamesTheRelayedKey(t *testing.T) {
	multiSelect := keymap().MultiSelect
	cases := map[string]string{
		"SelectAll":  multiSelect.SelectAll.Help().Key,
		"SelectNone": multiSelect.SelectNone.Help().Key,
	}
	for what, got := range cases {
		if got != selectAllKey {
			t.Errorf("%s help shows %q, want %q", what, got, selectAllKey)
		}
	}
}
