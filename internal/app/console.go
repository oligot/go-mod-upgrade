package app

import (
	"fmt"
	"io"
	"sync"
)

// console serialises everything written to the terminal, clearing a drawing
// spinner's line first so an entry does not land beside it.
//
// A spinner leaves the cursor part-way along a line, meaning to overwrite it by
// returning to column zero on its next tick. Anything written there joins it on that
// row. So a write takes the spinner's own lock, which its redraw also holds, and
// clears the line before writing: the write lands at column zero and the spinner
// redraws beneath it.
//
// One writer rather than a handler, because there is no longer a logging handler to
// hang this on: the logger is handed an io.Writer, and a listing and a policy report
// are writes too. Where the handler this replaces ordered only log entries against
// the spinner, every write through here is ordered against every other -- which is
// what the report at enforce.go and the listing never had.
type console struct {
	// mu is held for the whole of a write, so two writers cannot interleave a line.
	// Exported through hold for the callers that write directly rather than through
	// the logger.
	mu sync.Mutex
	// out is where writes land. Held rather than read from a variable so a test can
	// point one console somewhere without disturbing another.
	out io.Writer
}

// newConsole returns a console writing to out.
func newConsole(out io.Writer) *console { return &console{out: out} }

// Write clears a drawing spinner's line and writes p.
//
// The logger emits one entry per call, so the clear cannot land inside an entry: it
// precedes a whole line rather than a fragment of one.
func (c *console) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.write(p)
}

// write is Write without the lock, for a caller already holding it.
func (c *console) write(p []byte) (int, error) {
	spinning.Lock()
	s := spinning.at
	spinning.Unlock()
	if s == nil {
		return c.out.Write(p)
	}
	// Held across the write so a redraw cannot land between the clear and the line.
	s.Lock()
	defer s.Unlock()
	fmt.Fprint(progressOut, "\r\033[K")
	return c.out.Write(p)
}

// hold runs fn with the console held, for a caller writing straight to the terminal
// rather than through the logger.
//
// A legend and a policy report are several lines each, written with the fmt verbs
// rather than as log entries. Taking the lock around the whole of one keeps a log
// entry from landing in the middle of it, which holding it per line would not.
func (c *console) hold(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn()
}
