package prompt

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

var (
	keyUp     = tea.KeyPressMsg{Code: tea.KeyUp}
	keyDown   = tea.KeyPressMsg{Code: tea.KeyDown}
	keySlash  = tea.KeyPressMsg{Code: '/', Text: "/"}
	keyLetter = tea.KeyPressMsg{Code: 'a', Text: selectAllKey}
)

// newSelector builds a selector over three modules, ready to receive keys, and
// returns the slice the form writes the selection to.
//
// Only the first module's label contains the letter "a", so filtering on it
// tells the two readings of that key apart.
func newSelector(t *testing.T) (selector, []module.Module, *[]module.Module) {
	t.Helper()
	modules := []module.Module{
		mod(t, "a", "1.0.0", "1.0.1"),
		mod(t, "b", "2.0.0", "2.0.1"),
		mod(t, "c", "3.0.0", "3.0.1"),
	}
	selected := new([]module.Module)
	form, field := build(modules, len(modules), selected)
	s := selector{form: form, field: field}
	s.Init()
	return s, modules, selected
}

// hovered returns the module under the cursor, failing if there is none.
func hovered(t *testing.T, s selector) module.Module {
	t.Helper()
	got, ok := s.field.Hovered()
	if !ok {
		t.Fatal("no module hovered")
	}
	return got
}

// press sends key presses to the selector, as a user would.
func press(s selector, keys ...tea.KeyPressMsg) {
	for _, k := range keys {
		s.Update(k)
	}
}

// names lists the modules in a selection, for readable failures.
func names(modules []module.Module) []string {
	got := make([]string, 0, len(modules))
	for _, mod := range modules {
		got = append(got, mod.Name)
	}
	return got
}

// survey wrapped the cursor at both ends of the list; huh clamps it instead.
func TestSelectorUpFromFirstGoesToLast(t *testing.T) {
	s, modules, _ := newSelector(t)

	press(s, keyUp)

	if got, want := hovered(t, s), modules[len(modules)-1]; got != want {
		t.Errorf("up from the first module hovers %q, want the last (%q)", got.Name, want.Name)
	}
}

func TestSelectorDownFromLastGoesToFirst(t *testing.T) {
	s, modules, _ := newSelector(t)

	press(s, keyDown, keyDown, keyDown)

	if got, want := hovered(t, s), modules[0]; got != want {
		t.Errorf("down from the last module hovers %q, want the first (%q)", got.Name, want.Name)
	}
}

// The wrap fires on a cursor that could not move. Moves that land somewhere
// new must be left alone, or a plain up in the middle would jump to the end.
func TestSelectorLeavesInteriorMovesAlone(t *testing.T) {
	s, modules, _ := newSelector(t)

	press(s, keyDown, keyDown, keyUp)

	if got, want := hovered(t, s), modules[1]; got != want {
		t.Errorf("up from the last module hovers %q, want the middle one (%q)", got.Name, want.Name)
	}
}

// While the filter is open, huh ignores the jump keys and types them into the
// filter box instead, so wrapping there would spell "end" into the filter.
func TestSelectorDoesNotWrapWhileFiltering(t *testing.T) {
	s, modules, _ := newSelector(t)

	press(s, keySlash, keyUp)

	if !s.field.GetFiltering() {
		t.Fatal("filter did not open, test proves nothing")
	}
	if got, want := hovered(t, s), modules[0]; got != want {
		t.Errorf("up while filtering hovers %q, want the first module (%q) and no wrap", got.Name, want.Name)
	}
}

// npm-check-updates selects every package with "a", and so does this.
func TestSelectorLetterSelectsAll(t *testing.T) {
	s, modules, selected := newSelector(t)

	press(s, keyLetter)

	if len(*selected) != len(modules) {
		t.Errorf("%q selected %v, want all %v", selectAllKey, names(*selected), names(modules))
	}
}

// The same key selects none once everything is selected: huh drives both from
// one binding, and the help text flips to match.
func TestSelectorLetterSelectsNoneWhenAllSelected(t *testing.T) {
	s, _, selected := newSelector(t)

	press(s, keyLetter, keyLetter)

	if len(*selected) != 0 {
		t.Errorf("%q twice left %v selected, want nothing", selectAllKey, names(*selected))
	}
}

// The letter has to stay typeable in the filter, which is the whole reason it
// is relayed rather than bound.
func TestSelectorLetterTypesIntoTheFilter(t *testing.T) {
	s, modules, selected := newSelector(t)

	press(s, keySlash, keyLetter)

	if len(*selected) != 0 {
		t.Errorf("%q while filtering selected %v, want nothing", selectAllKey, names(*selected))
	}
	// Only the first module's label contains the letter, so it is the one the
	// filter must be left showing.
	if got, want := hovered(t, s), modules[0]; got != want {
		t.Errorf("filtering on %q hovers %q, want %q: the letter never reached the filter", selectAllKey, got.Name, want.Name)
	}
}
