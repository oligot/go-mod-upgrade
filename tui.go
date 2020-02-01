package main

import (
	"github.com/gdamore/tcell"
	"gitlab.com/tslocum/cbind"
	"gitlab.com/tslocum/cview"
)

var (
	app         *cview.Application
	inputConfig = cbind.NewConfiguration()

	updateList *cview.List

	currentFocus int
)

func initTUI() {
	cview.Styles.TitleColor = tcell.ColorDefault
	cview.Styles.BorderColor = tcell.ColorDefault
	cview.Styles.PrimaryTextColor = tcell.ColorDefault
	cview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault

	app = cview.NewApplication().
		SetInputCapture(inputConfig.Capture)

	updateList = cview.NewList().
		ShowSecondaryText(false).
		AddItem("Discovering modules...", "", 0, nil)

	pad := cview.NewTextView()

	grid := cview.NewGrid().
		SetRows(-1, -1).
		SetColumns(-1, -1).
		AddItem(updateList, 0, 0, 1, 2, 0, 0, true).
		AddItem(pad, 1, 0, 1, 2, 0, 0, true)

	app.SetRoot(grid, true).SetFocus(updateList)
}

func focusUpdated() {
	// TODO
}
