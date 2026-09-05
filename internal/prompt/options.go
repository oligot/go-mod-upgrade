package prompt

import (
	"fmt"

	"charm.land/huh/v2"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

// buildOptions renders one option per module, in the order given. Names and
// current versions are padded to a common width so the arrows line up. Each
// option carries its module as its value, so no index mapping is needed to
// recover the user's selection.
func buildOptions(modules []module.Module) []huh.Option[module.Module] {
	maxName, maxFrom := module.MaxWidths(modules)
	options := make([]huh.Option[module.Module], 0, len(modules))
	for _, mod := range modules {
		label := fmt.Sprintf(
			"%s %s -> %s",
			mod.FormatName(maxName),
			mod.FormatFrom(maxFrom),
			mod.FormatTo(),
		)
		options = append(options, huh.NewOption(label, mod))
	}
	return options
}
