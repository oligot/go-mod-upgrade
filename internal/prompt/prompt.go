// Package prompt asks the user which modules to update.
package prompt

import (
	"errors"
	"fmt"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// ErrAborted is returned when the user interrupts the selection with ctrl+c.
// It exists so callers can recognise an interrupt without importing huh.
var ErrAborted = errors.New("selection aborted")

// Choose asks the user which modules to update. The selected modules keep the
// order they were passed in. The prompt erases itself on exit.
func Choose(modules []module.Module, pageSize int) ([]module.Module, error) {
	var selected []module.Module
	if err := run(build(modules, pageSize, &selected)); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return nil, ErrAborted
		}
		return nil, fmt.Errorf("choosing modules: %w", err)
	}
	return selected, nil
}

// build returns the module selector, and the field within it that the cursor
// wrapping needs to watch.
func build(modules []module.Module, pageSize int, selected *[]module.Module) (*huh.Form, *huh.MultiSelect[module.Module]) {
	field := huh.NewMultiSelect[module.Module]().
		Title("Choose which modules to update").
		Options(buildOptions(modules)...).
		// huh's Height covers the whole field, title line included, so add
		// one to keep pageSize module rows visible.
		Height(pageSize + 1).
		Value(selected)
	form := huh.NewForm(huh.NewGroup(field)).WithTheme(theme()).WithKeyMap(keymap())
	return form, field
}

// run runs the form under [selector], in place of huh's own Run, which would
// put the form straight into bubbletea with nothing in between.
func run(form *huh.Form, field *huh.MultiSelect[module.Module]) error {
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Interrupt

	_, err := tea.NewProgram(selector{form: form, field: field}).Run()
	if form.State == huh.StateAborted || errors.Is(err, tea.ErrInterrupted) {
		return huh.ErrUserAborted
	}
	if err != nil {
		return fmt.Errorf("running the form: %w", err)
	}
	return nil
}
