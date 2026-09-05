package prompt

import (
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// selector is the model the form runs under. It sits between bubbletea and the
// form, rewriting key presses on their way in to restore two behaviours huh
// does not offer as options: a cursor that wraps at the ends of the list, and
// select-all on a bare letter.
//
// Both work by handing the form a different key than the one pressed, which is
// the only lever available from outside: the field's cursor and keymap are
// unexported once the form owns them.
type selector struct {
	form  *huh.Form
	field *huh.MultiSelect[module.Module]
}

func (s selector) Init() tea.Cmd {
	return s.form.Init()
}

func (s selector) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	msg = s.relaySelectAll(msg)
	jump, mayWrap := s.jump(msg)
	before, onModule := s.field.Hovered()

	// The form mutates itself and returns itself, so s stays valid.
	_, cmd := s.form.Update(msg)

	if !mayWrap || !onModule {
		return s, cmd
	}
	if after, _ := s.field.Hovered(); after != before {
		return s, cmd
	}
	_, jumpCmd := s.form.Update(jump)
	return s, tea.Batch(cmd, jumpCmd)
}

func (s selector) View() tea.View {
	var view tea.View
	// huh reports focus so it can dim the form when the terminal loses it.
	view.ReportFocus = true
	view.SetContent(s.form.View())
	return view
}

// relaySelectAll turns a press of [selectAllKey] into the key the select-all
// binding listens on, leaving every other message alone.
//
// The indirection is what keeps a bare letter usable as a shortcut. huh guards
// its other letter keys with a filtering check but not select-all, so binding
// the letter directly would swallow it whenever the user typed it into the
// filter. Relaying only while the filter is closed puts that guard back.
func (s selector) relaySelectAll(msg tea.Msg) tea.Msg {
	press, ok := msg.(tea.KeyPressMsg)
	if !ok || s.field.GetFiltering() || press.String() != selectAllKey {
		return msg
	}
	return tea.KeyPressMsg{Code: 't', Mod: tea.ModCtrl}
}

// jump returns the key that moves the cursor to the far end of the list, for a
// msg that tries to move it past the near end.
//
// survey wrapped the cursor at both ends; huh clamps it instead. The wrap is
// applied by [selector.Update] after the fact: if the hovered module did not
// change, the cursor was already against that end, so this key follows.
// Watching the cursor rather than computing the ends keeps that correct when a
// filter is narrowing the list, which is the part we cannot see from here.
//
// Nothing is returned while the filter is open: huh ignores the jump keys then
// and hands them to the filter input, which would type them into the box.
func (s selector) jump(msg tea.Msg) (tea.KeyPressMsg, bool) {
	press, ok := msg.(tea.KeyPressMsg)
	if !ok || s.field.GetFiltering() {
		return tea.KeyPressMsg{}, false
	}
	keys := keymap().MultiSelect
	switch {
	case key.Matches(press, keys.Up):
		return tea.KeyPressMsg{Code: tea.KeyEnd}, true
	case key.Matches(press, keys.Down):
		return tea.KeyPressMsg{Code: tea.KeyHome}, true
	}
	return tea.KeyPressMsg{}, false
}
