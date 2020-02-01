package main

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell"
	"gitlab.com/tslocum/cbind"
)

const (
	actionSelect        = "select"
	actionPreviousItem  = "previous-item"
	actionNextItem      = "next-item"
	actionPreviousPage  = "previous-page"
	actionNextPage      = "next-page"
	actionPreviousField = "previous-field"
	actionNextField     = "next-field"
	actionExit          = "exit"
)

var actionHandlers = map[string]func(*tcell.EventKey) *tcell.EventKey{
	actionSelect:        selectItem,
	actionPreviousItem:  previousItem,
	actionNextItem:      nextItem,
	actionPreviousPage:  previousPage,
	actionNextPage:      nextPage,
	actionPreviousField: previousField,
	actionNextField:     nextField,
	actionExit:          exit,
}

func setKeyBinds() error {
	if len(config.Input) == 0 {
		setDefaultKeyBinds()
	}

	for a, keys := range config.Input {
		a = strings.ToLower(a)
		handler := actionHandlers[a]
		if handler == nil {
			return fmt.Errorf("failed to set keybind for %s: unknown action", a)
		}

		for _, k := range keys {
			mod, key, ch, err := cbind.Decode(k)
			if err != nil {
				return fmt.Errorf("failed to set keybind %s for %s: %s", k, a, err)
			}

			if key == tcell.KeyRune {
				inputConfig.SetRune(mod, ch, handler)
			} else {
				inputConfig.SetKey(mod, key, handler)
			}
		}
	}

	return nil
}

func setDefaultKeyBinds() {
	config.Input = map[string][]string{
		actionSelect:        {"Enter"},
		actionPreviousItem:  {"Up", "k"},
		actionNextItem:      {"Down", "j"},
		actionPreviousPage:  {"PageUp"},
		actionNextPage:      {"PageDown"},
		actionPreviousField: {"Backtab"},
		actionNextField:     {"Tab"},
		actionExit:          {"Alt+q"},
	}
}

func selectItem(ev *tcell.EventKey) *tcell.EventKey {
	if currentFocus == 0 {
		return ev
	}

	return nil

}

func previousItem(ev *tcell.EventKey) *tcell.EventKey {
	if currentFocus == 0 {
		return ev
	}

	return nil

}

func nextItem(ev *tcell.EventKey) *tcell.EventKey {
	if currentFocus == 0 {
		return ev
	}

	return nil

}

func previousPage(ev *tcell.EventKey) *tcell.EventKey {
	if currentFocus == 0 {
		return ev
	}

	return nil

}

func nextPage(ev *tcell.EventKey) *tcell.EventKey {
	if currentFocus == 0 {
		return ev
	}

	return nil

}

func previousField(_ *tcell.EventKey) *tcell.EventKey {
	if currentFocus > 0 {
		currentFocus--
	}

	focusUpdated()

	return nil
}

func nextField(_ *tcell.EventKey) *tcell.EventKey {
	if currentFocus < 2 {
		currentFocus++
	}

	focusUpdated()

	return nil
}

func exit(_ *tcell.EventKey) *tcell.EventKey {
	return nil
}
