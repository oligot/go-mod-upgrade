package app

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/fatih/color"
)

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
	// filter narrows the list to the options containing it.
	filter string
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
	case key.Code == tea.KeyEnter:
		m.done = true
		return m, tea.Quit
	case key.Code == tea.KeyUp:
		// Held at the ends rather than wrapping: in a list long enough to scroll,
		// wrapping loses the reader's place.
		m.cursor = max(m.cursor-1, 0)
	case key.Code == tea.KeyDown:
		m.cursor = min(m.cursor+1, max(len(shown)-1, 0))
	case key.Code == tea.KeySpace:
		if m.cursor < len(shown) {
			at := shown[m.cursor]
			if _, had := m.marked[at]; had {
				delete(m.marked, at)
			} else {
				m.marked[at] = struct{}{}
			}
		}
	case key.Code == tea.KeyRight:
		// Everything shown, which with a filter means everything it admits.
		for _, at := range shown {
			m.marked[at] = struct{}{}
		}
	case key.Code == tea.KeyLeft:
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

// ask runs the prompt and returns the positions chosen, and whether the reader
// answered at all.
//
// Not answering is distinct from choosing nothing: one is an instruction to do
// nothing, the other is a reader who gave up, and only the first should be acted on.
func ask(message string, options []string, defaults []int, page int) (chosen []int, answered bool, err error) {
	// The prompt draws where the listing does, so the two are not interleaved.
	final, err := tea.NewProgram(
		newSelect(message, options, defaults, page),
		tea.WithOutput(color.Output),
	).Run()
	if err != nil {
		return nil, false, err
	}
	m, ok := final.(selectModel)
	if !ok {
		return nil, false, fmt.Errorf("prompt returned %T", final)
	}
	if m.interrupted {
		return nil, false, nil
	}
	return m.chosen(), m.done, nil
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
	b.WriteString("  [space to select, <right> all, <left> none, type to filter]\n")

	end := min(m.top+m.page, len(shown))
	for _, at := range shown[min(m.top, len(shown)):end] {
		cursor := " "
		if shown[m.cursor] == at {
			cursor = ">"
		}
		mark := " "
		if _, ok := m.marked[at]; ok {
			mark = "x"
		}
		fmt.Fprintf(&b, "%s [%s] %s\n", cursor, mark, m.options[at])
	}
	// How many the page leaves off, so a long list says that it is one.
	if left := len(shown) - end; left > 0 {
		fmt.Fprintf(&b, "%s\n", color.New(color.Faint).Sprintf("    ... %d more, scroll to see", left))
	}
	return tea.NewView(b.String())
}
