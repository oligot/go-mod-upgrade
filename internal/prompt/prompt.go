// Package prompt asks the user which modules to update.
package prompt

import (
	"errors"
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// ErrAborted is returned when the user interrupts the selection with ctrl+c.
// It exists so callers can recognise an interrupt without importing survey.
var ErrAborted = errors.New("selection aborted")

// multiSelect doesn't show the answer. It just resets the prompt, and the
// answers are shown afterwards.
type multiSelect struct {
	survey.MultiSelect
}

func (m multiSelect) Cleanup(config *survey.PromptConfig, val any) error {
	return m.Render("", nil)
}

// Choose asks the user which modules to update. The selected modules keep the
// order they were passed in.
func Choose(modules []module.Module, pageSize int) ([]module.Module, error) {
	maxName, maxFrom := module.MaxWidths(modules)
	options := []string{}
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		option := fmt.Sprintf("%s %s -> %s%s", x.FormatName(maxName), from, x.FormatTo(), x.FormatCooldown())
		options = append(options, option)
	}
	prompt := &multiSelect{
		survey.MultiSelect{
			Message:  "Choose which modules to update",
			Options:  options,
			PageSize: pageSize,
		},
	}
	choice := []int{}
	if err := survey.AskOne(prompt, &choice); err != nil {
		if errors.Is(err, term.InterruptErr) {
			return nil, ErrAborted
		}
		return nil, fmt.Errorf("choosing modules: %w", err)
	}
	updates := []module.Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates, nil
}
