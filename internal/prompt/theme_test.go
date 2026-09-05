package prompt

import (
	"testing"

	"charm.land/huh/v2"
)

// The selector relies on huh decorating nothing: the module formatters colour
// each option themselves, and survey drew no gutter down the left of the
// prompt. Both would break silently on a huh upgrade that changed ThemeBase, or
// if someone swapped in a decorating theme, so assert on the rendering itself.
func TestThemeDecoratesNothing(t *testing.T) {
	// Guard against a vacuous test: if Render were a no-op for every style in
	// this environment, the assertions below would pass no matter what.
	if got := huh.ThemeCharm(true).Focused.SelectedOption.Render("x"); got == "x" {
		t.Skipf("Render does not decorate in this environment (ThemeCharm gave %q), assertions would be vacuous", got)
	}

	for _, dark := range []bool{true, false} {
		styles := theme().Theme(dark)
		cases := map[string]string{
			"selected option":   styles.Focused.SelectedOption.Render("x"),
			"unselected option": styles.Focused.UnselectedOption.Render("x"),
			"field body":        styles.Focused.Base.Render("x"),
		}
		for what, got := range cases {
			if got != "x" {
				t.Errorf("dark=%v: %s renders %q, want %q undecorated", dark, what, got, "x")
			}
		}
	}
}
