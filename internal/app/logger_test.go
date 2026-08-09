package app

import (
	"testing"

	"github.com/rs/zerolog"
)

// TestVerbosityRisesWithTheCount checks that each --verbose raises the level by one
// step, and that the default leaves warnings visible.
//
// The count is what carries this, not the flag's value: urfave reports a repeated
// bool as false on its second appearance, so a level read from the value would make
// -vv quieter than -v. The table asserts the ordering that rules out, rather than
// only the individual answers.
func TestVerbosityRisesWithTheCount(t *testing.T) {
	for _, c := range []struct {
		name  string
		count int
		want  zerolog.Level
	}{
		{"no flag reports warnings but no chatter", 0, zerolog.InfoLevel},
		{"-v asks for debug", 1, zerolog.DebugLevel},
		{"-vv asks for trace", 2, zerolog.TraceLevel},
		{"-vvv has nothing further to give", 3, zerolog.TraceLevel},
		{"a count beyond the levels stays at trace", 9, zerolog.TraceLevel},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := verbosity(c.count); got != c.want {
				t.Errorf("verbosity(%d) = %v, want %v", c.count, got, c.want)
			}
		})
	}
}

// TestVerbosityNeverRisesWithMoreFlags checks that adding a flag never makes a run
// report less, which is the property a level read from a repeated bool breaks.
func TestVerbosityNeverRisesWithMoreFlags(t *testing.T) {
	for count := 1; count <= 4; count++ {
		if prev, got := verbosity(count-1), verbosity(count); got > prev {
			t.Errorf("verbosity(%d) = %v is quieter than verbosity(%d) = %v",
				count, got, count-1, prev)
		}
	}
}

// TestVerbosityKeepsWarningsWithoutAFlag checks that a default run still reports a
// warning and an error.
//
// Asserting the levels a reader sees, rather than the name of the level chosen: the
// point of the floor is that advisories that could not be fetched are not withheld
// until someone thinks to ask.
func TestVerbosityKeepsWarningsWithoutAFlag(t *testing.T) {
	level := verbosity(0)
	for _, l := range []zerolog.Level{zerolog.WarnLevel, zerolog.ErrorLevel} {
		if l < level {
			t.Errorf("a default run withholds %v", l)
		}
	}
	if zerolog.DebugLevel >= level {
		t.Errorf("a default run reports %v, which is the chatter the quiet default removes",
			zerolog.DebugLevel)
	}
}
