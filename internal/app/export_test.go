package app

import (
	"io"

	"github.com/apex/log"
	logcli "github.com/apex/log/handlers/cli"
	"github.com/briandowns/spinner"
)

// setProgressOutput sends both the spinners and the log handler to w, and returns
// a function restoring what was there before.
//
// The two have to share a destination for a test to see how they are ordered
// against each other, which is the whole of what the coordination does.
func setProgressOutput(w io.Writer) (restore func()) {
	prevOut, prevLog := progressOut, log.Log
	progressOut = w
	log.SetHandler(LogHandler(logcli.New(w)))
	return func() {
		progressOut = prevOut
		log.Log = prevLog
	}
}

// holdForTest registers s as the spinner drawing, without starting it.
//
// draw starts a spinner and registers it only if it drew, which needs a terminal
// the tests do not have. Registering directly stands in for that, so what an
// entry does about a drawing spinner can still be checked.
func holdForTest(s *spinner.Spinner) (release func()) {
	spinning.Lock()
	prev := spinning.at
	spinning.at = s
	spinning.Unlock()
	return func() {
		spinning.Lock()
		spinning.at = prev
		spinning.Unlock()
	}
}
