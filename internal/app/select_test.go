package app

import (
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// press sends a keystroke to the model and returns what it became.
func press(t *testing.T, m selectModel, keys ...string) selectModel {
	t.Helper()
	for _, key := range keys {
		next, _ := m.Update(tea.KeyPressMsg{Code: keyCode(key), Text: key})
		got, ok := next.(selectModel)
		if !ok {
			t.Fatalf("Update returned %T, want selectModel", next)
		}
		m = got
	}
	return m
}

// keyCode maps a test's shorthand onto the rune or special code bubbletea sends.
func keyCode(key string) rune {
	switch key {
	case "down":
		return tea.KeyDown
	case "up":
		return tea.KeyUp
	case "space":
		return tea.KeySpace
	case "right":
		return tea.KeyRight
	case "left":
		return tea.KeyLeft
	case "enter":
		return tea.KeyEnter
	}
	return rune(key[0])
}

// TestSelectTogglesUnderTheCursor checks that space marks the option the cursor is
// on, and marks it off again.
func TestSelectTogglesUnderTheCursor(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b", "c"}, nil, 10)

	m = press(t, m, "space")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chose %v, want the first option", got)
	}

	m = press(t, m, "down", "space")
	if got := m.chosen(); !slices.Equal(got, []int{0, 1}) {
		t.Errorf("chose %v, want the first two", got)
	}

	// Space again clears it, so a mistake is undone with the same key.
	m = press(t, m, "space")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chose %v, want the second cleared", got)
	}
}

// TestSelectStartsFromTheDefaults checks that a prompt can open with options
// already marked, which is how upgrading a module in every member that requires it
// is offered.
func TestSelectStartsFromTheDefaults(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b", "c"}, []int{0, 2}, 10)
	if got := m.chosen(); !slices.Equal(got, []int{0, 2}) {
		t.Errorf("chose %v, want the defaults", got)
	}
}

// TestSelectAllAndNone checks the two bulk keys, which is what makes a long list
// usable when the answer is nearly all or nearly none of it.
func TestSelectAllAndNone(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b", "c"}, nil, 10)

	m = press(t, m, "right")
	if got := m.chosen(); !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("chose %v, want everything", got)
	}
	m = press(t, m, "left")
	if got := m.chosen(); len(got) != 0 {
		t.Errorf("chose %v, want nothing", got)
	}
}

// TestSelectCursorStopsAtTheEnds checks that the cursor does not wrap.
//
// Wrapping in a list long enough to scroll loses the reader's place, and the list
// is as long as the module count.
func TestSelectCursorStopsAtTheEnds(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b"}, nil, 10)

	m = press(t, m, "up")
	if m.cursor != 0 {
		t.Errorf("cursor at %d, want it held at the top", m.cursor)
	}
	m = press(t, m, "down", "down", "down")
	if m.cursor != 1 {
		t.Errorf("cursor at %d, want it held at the last option", m.cursor)
	}
}

// TestSelectFilters checks that typing narrows the list, and that a choice is
// reported against the original options rather than the narrowed ones.
func TestSelectFilters(t *testing.T) {
	m := newSelect("Choose", []string{"alpha", "beta", "gamma"}, nil, 10)

	m = press(t, m, "b")
	if got := m.visible(); !slices.Equal(got, []int{1}) {
		t.Errorf("showing %v, want only the match", got)
	}
	// The marked option is the one the reader saw, which is the second overall.
	m = press(t, m, "space")
	if got := m.chosen(); !slices.Equal(got, []int{1}) {
		t.Errorf("chose %v, want the second option", got)
	}
}

// TestSelectReportsInterruption checks that ctrl+c is distinguishable from an
// answer, since abandoning a prompt must not read as choosing nothing.
func TestSelectReportsInterruption(t *testing.T) {
	m := newSelect("Choose", []string{"a"}, nil, 10)

	next, _ := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	got, ok := next.(selectModel)
	if !ok {
		t.Fatalf("Update returned %T, want selectModel", next)
	}
	if !got.interrupted {
		t.Error("ctrl+c did not mark the prompt interrupted")
	}
}

// TestSelectViewShowsPositionAndRemainder checks that the view says where the
// cursor is and that more options follow.
//
// A page that fills the window otherwise looks like the whole list, with nothing to
// say anything follows.
func TestSelectViewShowsPositionAndRemainder(t *testing.T) {
	options := []string{"a", "b", "c", "d", "e"}
	m := newSelect("Choose", options, nil, 3)

	view := m.View().Content
	if !strings.Contains(view, "[1/5]") {
		t.Errorf("view does not say the position:\n%s", view)
	}
	if !strings.Contains(view, "2 more") {
		t.Errorf("view does not say how many follow:\n%s", view)
	}
	// The page holds what it was sized for, and no more.
	if got := strings.Count(view, "\n"); got > 6 {
		t.Errorf("view is %d lines, want the page it was sized for:\n%s", got, view)
	}
}

// TestSelectFilterMatchingNothing checks that a filter admitting no option leaves a
// prompt that still renders and still answers.
//
// The cursor indexes the options shown, so an empty list is where an unguarded
// prompt indexes past the end.
func TestSelectFilterMatchingNothing(t *testing.T) {
	m := newSelect("Choose", []string{"alpha", "beta"}, nil, 5)

	m = press(t, m, "z", "z")
	if got := m.visible(); len(got) != 0 {
		t.Fatalf("showing %v, want nothing", got)
	}
	// Rendering must not index past the end of an empty list.
	if got := m.View().Content; !strings.Contains(got, "[0/0]") {
		t.Errorf("view does not say the list is empty:\n%s", got)
	}
	// Space has nothing to mark, and answering reports nothing rather than failing.
	m = press(t, m, "space", "enter")
	if got := m.chosen(); len(got) != 0 {
		t.Errorf("chose %v, want nothing", got)
	}
	if !m.done {
		t.Error("the prompt did not report an answer")
	}
}

// TestSelectBackspaceWidensTheFilter checks that a filter can be corrected, since
// mistyping one would otherwise mean abandoning the prompt.
func TestSelectBackspaceWidensTheFilter(t *testing.T) {
	m := newSelect("Choose", []string{"alpha", "beta"}, nil, 5)

	m = press(t, m, "b", "z")
	if got := m.visible(); len(got) != 0 {
		t.Fatalf("showing %v, want nothing", got)
	}
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyBackspace})
	m = next.(selectModel)
	if got := m.visible(); !slices.Equal(got, []int{1}) {
		t.Errorf("showing %v, want the match back", got)
	}
}

// TestSelectPinsAHeading checks that a heading given to the prompt stays above the
// options rather than scrolling with them.
//
// The old prompt could not pin a row, so the columns went unlabelled and a reader
// had to know what six of them meant. Owning the view is what makes it possible.
func TestSelectPinsAHeading(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b", "c", "d", "e"}, nil, 2)
	m.heading = "MODULE  FROM  TO"

	view := m.View().Content
	if !strings.Contains(view, "MODULE  FROM  TO") {
		t.Fatalf("the heading is missing:\n%s", view)
	}
	// Above the options, so it reads as their heading rather than as one of them.
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	at := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "MODULE") })
	first := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "[ ] a") })
	if at < 0 || first < 0 || at > first {
		t.Errorf("heading at line %d, first option at %d, want the heading first:\n%s", at, first, view)
	}

	// Scrolling past the page does not take it with them.
	m = press(t, m, "down", "down", "down")
	if !strings.Contains(m.View().Content, "MODULE  FROM  TO") {
		t.Errorf("the heading scrolled away with the options:\n%s", m.View().Content)
	}
}

// TestSelectWithoutAHeading checks that a prompt given none does not leave a blank
// line where one would be.
func TestSelectWithoutAHeading(t *testing.T) {
	m := newSelect("Choose", []string{"a"}, nil, 5)
	if got := m.View().Content; strings.Contains(got, "\n\n") {
		t.Errorf("view holds a blank line with no heading to show:\n%q", got)
	}
}

// TestSelectPageFollowsTheCursor checks that moving past the end of a page scrolls
// rather than hiding the cursor.
func TestSelectPageFollowsTheCursor(t *testing.T) {
	m := newSelect("Choose", []string{"a", "b", "c", "d", "e"}, nil, 3)

	m = press(t, m, "down", "down", "down")
	if !strings.Contains(m.View().Content, "d") {
		t.Errorf("the cursor's option is not on the page:\n%s", m.View().Content)
	}
	if !strings.Contains(m.View().Content, "[4/5]") {
		t.Errorf("view does not track the position:\n%s", m.View().Content)
	}
}
