package app

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// markerWidth is how many columns a row's prefix occupies: the cursor, a space, the
// marker in its brackets, and a space -- "> [x] ".
//
// A heading is indented by it so the columns land under their labels, and the listing
// sizes its columns by it so they fit once prefixed. Both read it from here rather than
// each carrying a 6 that has to be kept in step.
const markerWidth = len("> [x] ")

// selectModel is the multi-select prompt: a list of options, some marked, one under
// the cursor.
//
// The options are rendered by the caller, so this knows nothing of modules. It
// answers with positions in the list it was given, which is what lets one prompt
// choose modules and another choose the members of a workspace.
type selectModel struct {
	message string
	options []string
	// marked records the options chosen, by position in options.
	marked map[int]struct{}
	// cursor is the position within the options currently shown, so it tracks the
	// filtered list rather than the whole one.
	cursor int
	// top is the first option on the page, moved only when the cursor would leave
	// it, so the list scrolls rather than jumping.
	top int
	// page is how many options are shown at once.
	page int
	// heading labels the columns of the options, pinned above them so it does not
	// scroll away or read as one of them. Empty when the options need no heading.
	heading string
	// filter narrows the list to the options containing it.
	filter string
	// single asks a question admitting exactly one answer, so marking an option
	// replaces whatever was marked rather than joining it.
	//
	// Which modules to upgrade is a list; which version of one module to install is
	// not. Without this the prompt could show two marks while the caller could only
	// act on one, which makes the display a lie about what will happen.
	single bool
	// disabled records the options that cannot be chosen, by position in options.
	//
	// They are shown rather than dropped, because a reader who cannot have the newest
	// version needs to see that it exists and why it is refused -- a list it silently
	// vanished from would read as the newest not existing. But it cannot be selected:
	// accepting a choice and then installing something else is the same lie as showing
	// two marks and honouring one.
	//
	// Only consulted for a single-answer prompt, which is the only kind that has
	// anything refusable in it.
	disabled map[int]struct{}
	// done reports that the reader answered, interrupted that they gave up. The
	// two are distinct: abandoning a prompt must not read as choosing nothing.
	done        bool
	interrupted bool
}

// newSelect returns a prompt over the options, with those at the given positions
// already marked.
func newSelect(message string, options []string, defaults []int, page int) selectModel {
	marked := make(map[int]struct{}, len(defaults))
	for _, at := range defaults {
		marked[at] = struct{}{}
	}
	return selectModel{
		message: message,
		options: options,
		marked:  marked,
		page:    max(page, 1),
	}
}

// visible returns the positions the filter admits, in order.
func (m selectModel) visible() []int {
	out := make([]int, 0, len(m.options))
	for i, option := range m.options {
		if m.filter == "" || strings.Contains(strings.ToLower(option), strings.ToLower(m.filter)) {
			out = append(out, i)
		}
	}
	return out
}

// chosen returns the marked positions, in the order the options were given.
func (m selectModel) chosen() []int {
	out := make([]int, 0, len(m.marked))
	for i := range m.options {
		if _, ok := m.marked[i]; ok {
			out = append(out, i)
		}
	}
	return out
}

// blocked reports whether the option at a position in the whole list cannot be
// chosen. Only a single-answer prompt refuses anything.
func (m selectModel) blocked(at int) bool {
	if !m.single {
		return false
	}
	_, ok := m.disabled[at]
	return ok
}

// moveTo moves the cursor by one, skipping over anything that cannot be chosen so that
// what is under it is always what enter would take.
//
// Held at the ends rather than wrapping, and held where it is when there is nothing
// available beyond: a cursor that landed on a refused option would invite a reader to
// press space and watch nothing happen.
func (m selectModel) moveTo(shown []int, by int) int {
	for at := m.cursor + by; at >= 0 && at < len(shown); at += by {
		if !m.blocked(shown[at]) {
			return at
		}
	}
	return m.cursor
}

func (m selectModel) Init() tea.Cmd { return nil }

func (m selectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	shown := m.visible()

	switch {
	case key.Mod&tea.ModCtrl != 0 && (key.Code == 'c' || key.Code == 'd'):
		m.interrupted = true
		return m, tea.Quit
	case key.Code == tea.KeyEscape:
		m.interrupted = true
		return m, tea.Quit
	case key.Code == 'q' && key.Mod == 0 && m.filter == "":
		// Only while nothing is being typed: a reader narrowing to "sqlite" is not
		// asking to quit. Ctrl-C alone was a poor answer for a full-screen list, since
		// a reader reaching for q typed it into the filter and saw nothing happen.
		m.interrupted = true
		return m, tea.Quit
	case key.Code == tea.KeyEnter:
		m.done = true
		return m, tea.Quit
	case key.Code == tea.KeyUp:
		// Held at the ends rather than wrapping: in a list long enough to scroll,
		// wrapping loses the reader's place.
		m.cursor = m.moveTo(shown, -1)
	case key.Code == tea.KeyDown:
		m.cursor = m.moveTo(shown, +1)
	case key.Code == tea.KeySpace:
		if m.cursor < len(shown) {
			at := shown[m.cursor]
			switch {
			case m.blocked(at):
				// Refused, so the answer is left alone. Selecting it and quietly
				// installing something else would be worse than declining here.
			case m.single:
				// One answer, so this becomes it. Marking what is already chosen
				// leaves it chosen: a question needing an answer has no "none of
				// them", and toggling to empty would offer one.
				clear(m.marked)
				m.marked[at] = struct{}{}
			default:
				if _, had := m.marked[at]; had {
					delete(m.marked, at)
				} else {
					m.marked[at] = struct{}{}
				}
			}
		}
	case key.Code == tea.KeyRight:
		// Meaningless when one answer is wanted, so it does nothing rather than
		// marking every option and leaving the reader to undo it.
		if m.single {
			break
		}
		// Everything shown, which with a filter means everything it admits.
		for _, at := range shown {
			m.marked[at] = struct{}{}
		}
	case key.Code == tea.KeyLeft:
		if m.single {
			break
		}
		for _, at := range shown {
			delete(m.marked, at)
		}
	case key.Code == tea.KeyBackspace:
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
			m.cursor, m.top = 0, 0
		}
	case key.Text != "":
		m.filter += key.Text
		m.cursor, m.top = 0, 0
	}

	// The page follows the cursor, moving only far enough to keep it in view.
	shown = m.visible()
	if m.cursor >= len(shown) {
		m.cursor = max(len(shown)-1, 0)
	}
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+m.page {
		m.top = m.cursor - m.page + 1
	}
	return m, nil
}

// legendLevel is how much of a key a listing gets.
type legendLevel int

const (
	// legendNone writes no key. What a parseable listing gets, and what --legend=false
	// asks for.
	legendNone legendLevel = iota
	// legendTerse names each letter and the --labels key selecting it, on one line.
	legendTerse
	// legendFull explains each letter at length, one per line.
	legendFull
)

// legendPrefix introduces the key, so a reader can tell it from the listing it
// explains rather than meeting a bare letter and a sentence.
const legendPrefix = "LEGEND:"

// legendFor decides how much of a key to write.
//
// Off unless a person is reading, since a parseable listing has no colour to paint the
// letters with and a reader who looks a label key up rather than reading prose. A
// count beyond -LL has nothing further to give, as -vvv does not.
//
// The count decides this, never the flag's own value: urfave reports a repeated bool
// as false the second time, so -LL read from the value would ask for less than -L.
// The value is read only to turn the key off, which is the one thing a count cannot
// say -- --legend=false gives a count of one and a value of false.
func legendFor(count int, off, human bool) legendLevel {
	if !human || off {
		return legendNone
	}
	if count >= 2 {
		return legendFull
	}
	return legendTerse
}

// legend explains the labels a set of modules carries, once, before the rows that
// use them.
//
// A reader meeting "iD" in a column has to guess, so this is not a debug line: every
// informational line moved to debug, which would have hidden the key from the default
// run whose listing needs it. It is written beside the listing, on stderr as the
// policy report is, so that what goes to stdout stays parseable.
//
// Skipped when no module carries a label, which is what keeps a key out of a listing
// needing none.
func legend(modules []module.Module, level legendLevel) {
	var out string
	switch level {
	case legendNone:
		return
	case legendFull:
		lines := module.LegendLines(modules)
		if len(lines) == 0 {
			return
		}
		// The prefix on its own, since each entry needs a line to itself: several of
		// the descriptions contain a comma, so they cannot share one.
		out = legendPrefix + "\n\t" + strings.Join(lines, "\n\t") + "\n"
	default:
		text := module.Legend(modules)
		if text == "" {
			return
		}
		// One line, the whole key being short enough to read at a glance: it names
		// the letters rather than explaining them.
		out = legendPrefix + "\t" + text + "\n"
	}
	// Held for the write so a log entry cannot land inside it. One hold rather than
	// one per line, since the key is read as a block.
	terminal.hold(func() {
		if _, err := fmt.Fprint(color.Error, out); err != nil {
			log.Error().Err(err).Msg("Error while reporting the legend")
		}
	})
}

// askMulti runs the prompt and returns the positions chosen, and whether the reader
// answered at all.
//
// Not answering is distinct from choosing nothing: one is an instruction to do
// nothing, the other is a reader who gave up, and only the first should be acted on.
func askMulti(message, heading string, options []string, defaults []int, page int) (chosen []int, answered bool, err error) {
	return run(newSelect(message, options, defaults, page), heading)
}

// askSingle runs a prompt admitting exactly one answer, starting on the option at start.
//
// The marker is round rather than square and marking replaces rather than accumulates,
// so the list cannot show two answers where the caller can act on one. Options named in
// disabled are shown but cannot be chosen, and the cursor skips over them.
func askSingle(message, heading string, options []string, start, page int, disabled map[int]struct{}) (chosen int, answered bool, err error) {
	m := newSelect(message, options, []int{start}, page)
	m.single = true
	m.disabled = disabled
	m.cursor = start
	got, answered, err := run(m, heading)
	if err != nil || !answered || len(got) == 0 {
		return -1, answered, err
	}
	return got[0], true, nil
}

// run drives a prompt to its answer, shared by the two ways of asking.
func run(m selectModel, heading string) (chosen []int, answered bool, err error) {
	m.heading = heading
	// The prompt draws where the listing does, so the two are not interleaved.
	final, err := tea.NewProgram(m, tea.WithOutput(color.Output)).Run()
	if err != nil {
		return nil, false, err
	}
	got, ok := final.(selectModel)
	if !ok {
		return nil, false, fmt.Errorf("prompt returned %T", final)
	}
	if got.interrupted {
		return nil, false, nil
	}
	return got.chosen(), got.done, nil
}

func (m selectModel) View() tea.View {
	shown := m.visible()
	var b strings.Builder

	fmt.Fprintf(&b, "? %s", m.message)
	if m.filter != "" {
		fmt.Fprintf(&b, " %s", m.filter)
	}
	// Where the cursor is within the whole list, since a page that fills the window
	// otherwise looks like all of it.
	fmt.Fprintf(&b, " [%d/%d]", min(m.cursor+1, len(shown)), len(shown))
	// Only the keys that do something here, since offering all/none for a question
	// admitting one answer invites a reader to press them and see nothing happen.
	if m.single {
		b.WriteString("  [space to choose, type to filter, q to quit]\n")
	} else {
		b.WriteString("  [space to select, <right> all, <left> none, type to filter, q to quit]\n")
	}

	// Pinned above the options, indented past the marker so the columns line up with
	// what they label.
	//
	// The indent is the width of a row's prefix -- cursor, space, marker, space, as in
	// "> [x] " -- rather than a number chosen to look right. measure sizes the
	// listing's columns expecting exactly this, so the two cannot drift apart.
	if m.heading != "" {
		fmt.Fprintf(&b, "%s%s\n", strings.Repeat(" ", markerWidth), m.heading)
	}

	end := min(m.top+m.page, len(shown))
	// Square brackets for a list, round for one answer, following the checkbox and
	// radio button they stand in for: the shape says whether marking a second option
	// adds to the first or replaces it, before a reader presses anything.
	open, close := "[", "]"
	if m.single {
		open, close = "(", ")"
	}
	for _, at := range shown[min(m.top, len(shown)):end] {
		cursor := " "
		if shown[m.cursor] == at {
			cursor = ">"
		}
		mark := " "
		if _, ok := m.marked[at]; ok {
			mark = "x"
		}
		// A refused option is dashed rather than left empty, since empty reads as
		// "not chosen yet" and invites a reader to try, and dimmed so the row looks
		// unavailable before its text is read.
		if m.blocked(at) {
			fmt.Fprintf(&b, "%s %s-%s %s\n", cursor, open, close,
				module.FormatDisabled(m.options[at]))
			continue
		}
		fmt.Fprintf(&b, "%s %s%s%s %s\n", cursor, open, mark, close, m.options[at])
	}
	// How many the page leaves off, so a long list says that it is one.
	if left := len(shown) - end; left > 0 {
		fmt.Fprintf(&b, "%s\n", color.New(color.Faint).Sprintf("    ... %d more, scroll to see", left))
	}
	return tea.NewView(b.String())
}
