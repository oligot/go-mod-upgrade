package app

import (
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// terminal serialises everything written to the terminal: log entries, the legend,
// and the policy report.
//
// A global for the same reason the spinner registry is one. The writers it orders
// are in different packages of the run and none of them owns the others, so the
// lock cannot belong to any one of them. Points at stderr from the start so that a
// direct writer taking it before logging is configured still takes a real lock.
var terminal = newConsole(os.Stderr)

// logForReader reports whether log entries are being written for a person, which
// decides how a period in a field is spelled: the largest unit that fits for someone
// reading, whole seconds for something parsing.
//
// Derived from interactive() by logging rather than answered again here, so the log
// and the listing cannot disagree about who is reading. A global for the same reason
// the logger is one -- the values that render themselves are built in functions that
// never see an AppEnv. False by default, so anything logged before the flags parse is
// machine-readable rather than guessing.
var logForReader bool

// logging points the global logger at the terminal and sets the level from the
// count of --verbose flags.
//
// Called from Run rather than from main, because both of the facts it needs -- who
// is reading, and whether to paint -- are only settled once the flags have parsed.
//
// The logger stays a package global. Every one of the call sites logs through it,
// and threading a logger to each would change their shape without changing what
// they report.
func (app *AppEnv) logging() {
	zerolog.SetGlobalLevel(verbosity(app.Verbose))
	logForReader = app.interactive()
	if logForReader {
		log.Logger = zerolog.New(humanWriter(terminal, app.Color))
		return
	}
	// Nobody is reading, so the entries are for a program: JSON, and with the
	// timestamp a person did not need.
	log.Logger = zerolog.New(terminal).With().Timestamp().Logger()
}

// humanWriter renders entries for a person reading them as they arrive.
//
// Shared with the tests rather than each building its own, so that what a test
// asserts about a rendered entry is what a reader is shown.
//
// A timestamp is left out: every line of a foreground tool would carry very nearly
// the same one, and what a phase cost is reported by ReportTiming instead.
func humanWriter(out io.Writer, paint bool) zerolog.ConsoleWriter {
	return zerolog.ConsoleWriter{
		Out:          out,
		NoColor:      !paint,
		PartsExclude: []string{zerolog.TimestampFieldName},
	}
}

// verbosity maps the number of times --verbose was given to a level.
//
// Arithmetic rather than a table, because zerolog orders its levels as numbers:
// none is info, -v is debug, -vv is trace, and anything further is trace still.
//
// The count decides this, never the flag's own value. A repeated bool reports true
// once and false the second time, so a level read from the value would make -vv
// quieter than -v.
//
// Info is the floor rather than warn: a default run reports nothing at info, every
// informational line having moved to debug, but a warning a reader can act on --
// advisories that could not be fetched, a cache that could not be read -- is not
// something to withhold until asked.
func verbosity(count int) zerolog.Level {
	level := zerolog.InfoLevel - zerolog.Level(count)
	if level < zerolog.TraceLevel {
		return zerolog.TraceLevel
	}
	return level
}
