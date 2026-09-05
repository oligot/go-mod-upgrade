package prompt

import (
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// theme returns an uncoloured theme for the module selector.
//
// huh renders every option through SelectedOption or UnselectedOption, which
// would wrap the whole line in a single foreground colour and fight the
// per-token colours the module formatters already embed. Clearing both leaves
// huh in charge of the cursor and the checkbox prefixes only, so selection
// state reads from the prefix, as it did under survey.
//
// Focused.Base is cleared for a different reason: it carries a thick left
// border and padding that would draw a gutter down the left of the prompt.
func theme() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		styles := huh.ThemeBase(isDark)
		styles.Focused.SelectedOption = lipgloss.NewStyle()
		styles.Focused.UnselectedOption = lipgloss.NewStyle()
		styles.Focused.Base = lipgloss.NewStyle()
		styles.Focused.Card = styles.Focused.Base
		styles.Blurred.Base = styles.Focused.Base
		styles.Blurred.Card = styles.Focused.Base
		return styles
	})
}
