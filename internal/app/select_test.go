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

// TestSelectSingleHoldsOneAnswer checks that a prompt asking a one-answer question
// cannot end up showing two.
//
// Some questions admit exactly one answer -- which version of a module to install.
// Marking a second option there is a reader changing their mind, not asking for both,
// so it replaces rather than accumulates. Anything else lets the list display a
// selection the caller cannot honour.
func TestSelectSingleHoldsOneAnswer(t *testing.T) {
	options := []string{"a", "b", "c"}

	m := newSelect("Which?", options, []int{2}, 10)
	m.single = true
	m.cursor = 2

	// Moving up and marking replaces the default rather than joining it.
	m = press(t, m, "up", " ")
	if got := m.chosen(); !slices.Equal(got, []int{1}) {
		t.Errorf("chosen() = %v, want [1]", got)
	}
	// And again, so the answer follows the last thing marked.
	m = press(t, m, "up", " ")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chosen() = %v, want [0]", got)
	}
	// Marking what is already chosen leaves it chosen: a question needing an answer
	// has no "none of them", and toggling to empty would offer one.
	m = press(t, m, " ")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chosen() = %v, want [0] still", got)
	}
	// Select-all and select-none are meaningless for one answer, so they do nothing
	// rather than marking every option.
	m = press(t, m, "right")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("after all: chosen() = %v, want [0]", got)
	}
	m = press(t, m, "left")
	if got := m.chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("after none: chosen() = %v, want [0]", got)
	}
}

// TestSelectMultiStillAccumulates checks that the ordinary prompt is unchanged, since
// choosing several modules to upgrade is the usual case.
func TestSelectMultiStillAccumulates(t *testing.T) {
	m := newSelect("Which?", []string{"a", "b", "c"}, []int{2}, 10)
	m.cursor = 2
	m = press(t, m, "up", " ")
	if got := m.chosen(); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("chosen() = %v, want [1 2]", got)
	}
	m = press(t, m, "right")
	if got := m.chosen(); !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("after all: chosen() = %v, want every option", got)
	}
}

// TestSelectMarkerShape checks that the marker says which kind of question is being
// asked: square for a list, round for one answer.
//
// It borrows the checkbox and radio button because a reader already knows what those
// mean. Reading the shape is faster than pressing space twice and inferring the rule.
func TestSelectMarkerShape(t *testing.T) {
	options := []string{"a", "b"}

	multi := newSelect("Which?", options, []int{0}, 10).View().Content
	if !strings.Contains(multi, "[x]") {
		t.Errorf("multi-select view %q does not use square brackets", multi)
	}

	m := newSelect("Which?", options, []int{0}, 10)
	m.single = true
	single := m.View().Content
	if !strings.Contains(single, "(x)") {
		t.Errorf("single-select view %q does not use round brackets", single)
	}
	if strings.Contains(single, "[x]") || strings.Contains(single, "[ ]") {
		t.Errorf("single-select view %q still uses square brackets", single)
	}
	// The unmarked option follows the same shape, or the column reads as ragged.
	if !strings.Contains(single, "( )") {
		t.Errorf("single-select view %q does not round an unmarked option", single)
	}
	// The keys it advertises are the ones that work.
	if strings.Contains(single, "all") || strings.Contains(single, "none") {
		t.Errorf("single-select view %q offers keys that do nothing", single)
	}
}

// TestSelectDisabledCannotBeChosen checks that an option the caller marked unavailable
// cannot be selected, and that the cursor does not rest on one.
//
// A prompt that accepts a choice and then substitutes another is lying about what it
// did. Refusing the choice up front is the only version of this that a reader can
// trust: what is under the cursor is what enter will take.
func TestSelectDisabledCannotBeChosen(t *testing.T) {
	// Two denied, one available -- the shape the version prompt takes when a policy
	// caps a module below its newest releases.
	m := newSelect("Which?", []string{"a", "b", "c"}, []int{2}, 10)
	m.single = true
	m.disabled = map[int]struct{}{0: {}, 1: {}}
	m.cursor = 2

	// Space on a disabled option leaves the answer alone rather than moving it.
	up := press(t, m, "up", " ")
	if got := up.chosen(); !slices.Equal(got, []int{2}) {
		t.Errorf("chosen() = %v, want [2] left alone", got)
	}
	// And again further up, so it is the option that is refused rather than one
	// particular row.
	up = press(t, up, "up", " ")
	if got := up.chosen(); !slices.Equal(got, []int{2}) {
		t.Errorf("chosen() = %v, want [2] still", got)
	}

	// Moving up from the only available option skips over both denials rather than
	// resting on them, so the cursor is always on something enter can take.
	moved := press(t, m, "up")
	if moved.cursor != 2 {
		t.Errorf("cursor = %d, want it held at 2 with nothing available above", moved.cursor)
	}

	// An available option above a denial is still reachable: skipping is not the same
	// as stopping.
	m = newSelect("Which?", []string{"a", "b", "c"}, []int{2}, 10)
	m.single = true
	m.disabled = map[int]struct{}{1: {}}
	m.cursor = 2
	if got := press(t, m, "up").cursor; got != 0 {
		t.Errorf("cursor = %d, want 0, skipping the denial at 1", got)
	}
	if got := press(t, m, "up", " ").chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chosen() = %v, want [0]", got)
	}
}

// TestSelectDisabledShowsWhy checks that a refused option looks refused, so the reason
// is not carried by the row text alone.
func TestSelectDisabledShowsWhy(t *testing.T) {
	m := newSelect("Which?", []string{"available", "refused"}, []int{0}, 10)
	m.single = true
	m.disabled = map[int]struct{}{1: {}}

	view := m.View().Content
	// A dash rather than an empty marker: empty reads as "not chosen yet", which
	// invites a reader to try.
	if !strings.Contains(view, "(-) refused") {
		t.Errorf("view does not mark the refused option:\n%s", view)
	}
	// The available one keeps the ordinary markers.
	if !strings.Contains(view, "(x) available") {
		t.Errorf("view does not mark the available option:\n%s", view)
	}
}

// TestSelectDisabledIgnoredWhenMulti checks that the ordinary prompt is unaffected,
// since nothing there is refused.
func TestSelectDisabledIgnoredWhenMulti(t *testing.T) {
	m := newSelect("Which?", []string{"a", "b"}, nil, 10)
	m.disabled = map[int]struct{}{0: {}}
	if got := press(t, m, " ").chosen(); !slices.Equal(got, []int{0}) {
		t.Errorf("chosen() = %v, want [0]: a multi-select prompt disables nothing", got)
	}
}

// TestSelectHeadingAlignsWithTheOptions checks that a heading sits directly above the
// text it labels rather than over the marker.
//
// Each row is prefixed "> [x] " -- six characters -- so a heading indented by any other
// amount labels the wrong columns. The listing sizes its columns expecting that prefix
// (measure is called with 6), which is what makes this the number rather than a taste.
func TestSelectHeadingAlignsWithTheOptions(t *testing.T) {
	for _, single := range []bool{false, true} {
		m := newSelect("Choose", []string{"github.com/aws/smithy-go  1.27.3"}, nil, 10)
		m.single = single
		m.heading = "MODULE                    FROM"

		lines := strings.Split(strings.TrimRight(m.View().Content, "\n"), "\n")
		head := lines[slices.IndexFunc(lines, func(l string) bool {
			return strings.Contains(l, "MODULE")
		})]
		row := lines[slices.IndexFunc(lines, func(l string) bool {
			return strings.Contains(l, "smithy-go")
		})]

		// The first heading starts where the first option's text does.
		if strings.Index(head, "MODULE") != strings.Index(row, "github.com") {
			t.Errorf("single=%v: heading is not above the option text:\n%q\n%q", single, head, row)
		}
		// And so does the last, which is what catches an indent that is merely
		// consistent rather than correct.
		if strings.Index(head, "FROM") != strings.Index(row, "1.27.3") {
			t.Errorf("single=%v: later columns drift:\n%q\n%q", single, head, row)
		}
	}
}

// TestSelectQuits checks the keys that abandon a prompt.
//
// Ctrl-C was the only way out, which is a poor answer for a full-screen list: a reader reaching
// for q typed it into the filter instead and saw nothing happen. Esc is the other habit worth
// honouring.
//
// Abandoning is distinct from choosing nothing, which is why it sets interrupted rather than
// done: one is an instruction to do nothing, the other a reader who gave up, and only the first
// should be acted on.
func TestSelectQuits(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(selectModel) selectModel
	}{{
		name: "q",
		send: func(m selectModel) selectModel {
			return press(t, m, "q")
		},
	}, {
		name: "escape",
		send: func(m selectModel) selectModel {
			next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
			return next.(selectModel)
		},
	}, {
		name: "ctrl-c",
		send: func(m selectModel) selectModel {
			next, _ := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
			return next.(selectModel)
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.send(newSelect("Choose", []string{"a", "b"}, nil, 10))
			if !got.interrupted {
				t.Errorf("%s did not interrupt the prompt", tc.name)
			}
			if got.done {
				t.Errorf("%s reports an answer, want abandonment", tc.name)
			}
		})
	}

	// While a filter is being typed, q belongs to the filter: a reader narrowing to "sqlite"
	// is not asking to quit.
	m := press(t, newSelect("Choose", []string{"sqlite", "other"}, nil, 10), "s", "q")
	if m.interrupted {
		t.Error("q interrupted the prompt while filtering, want it typed into the filter")
	}
	if m.filter != "sq" {
		t.Errorf("filter = %q, want %q", m.filter, "sq")
	}
	// And the help line says how to leave, since a reader who cannot find the exit will use
	// ctrl-c and wonder whether the run was left half-done.
	if !strings.Contains(m.View().Content, "quit") {
		t.Errorf("view does not say how to quit:\n%s", m.View().Content)
	}
}
