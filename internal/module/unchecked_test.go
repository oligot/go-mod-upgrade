package module

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDeltaKeepsAnUncheckedModule checks which modules the default filter keeps once "unchecked"
// exists.
//
// The cases share a shape on purpose: an unchecked module has To equal to From, since there is no
// newer version to name, which is exactly the shape of a module with nothing to upgrade to. So
// the versions cannot be what decides it -- only the flag can. The delta filter is the default,
// so getting this wrong drops the row and lets an offline run report a clean tree it never
// examined.
func TestDeltaKeepsAnUncheckedModule(t *testing.T) {
	tests := []struct {
		name      string
		from, to  string
		unchecked bool
		// wantKept is how many of the one module given survives the filter.
		wantKept int
	}{
		{
			// Nothing was learned, so the row must stand: there may well be an
			// upgrade waiting behind it.
			name:      "an unchecked module is kept though it shows no delta",
			from:      "v1.0.0",
			to:        "v1.0.0",
			unchecked: true,
			wantKept:  1,
		},
		{
			// The same versions, checked. This is a real answer, so it is dropped
			// as it always was -- the flag is the only difference from the case
			// above.
			name:      "a module known to be current is dropped",
			from:      "v1.0.0",
			to:        "v1.0.0",
			unchecked: false,
			wantKept:  0,
		},
		{
			name:     "an ordinary upgrade is kept",
			from:     "v1.0.0",
			to:       "v1.1.0",
			wantKept: 1,
		},
		{
			// Unchecked yet somehow carrying a delta, from a cached answer reused
			// offline. The delta alone is reason to keep it.
			name:      "an unchecked module with an upgrade is kept",
			from:      "v1.0.0",
			to:        "v1.1.0",
			unchecked: true,
			wantKept:  1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := mod(t, "example.com/m", tc.from, tc.to, false)
			m.Unchecked = tc.unchecked

			// Through ParseFilter rather than by building a Filter here: Keys is
			// only the chain as given, for reporting, and the predicates that do
			// the work live in unexported fields. A hand-built Filter has an empty
			// keep list, which keeps everything and tests nothing.
			show, err := ParseFilter("", []string{FilterDelta})
			require.NoError(t, err)

			kept := Apply([]Module{m}, show)
			require.Len(t, kept, tc.wantKept)
		})
	}
}

// TestUncheckedLabelsTheRow checks that an unchecked module is marked, so a reader can see which
// rows report what is required rather than what is available.
//
// A row reading "v1.0.0 -> v1.0.0" with no mark is a claim that nothing newer exists. The mark is
// what makes it a question instead.
func TestUncheckedLabelsTheRow(t *testing.T) {
	tests := []struct {
		name      string
		unchecked bool
		wantMark  bool
	}{
		{
			name:      "an unchecked module is marked",
			unchecked: true,
			wantMark:  true,
		},
		{
			name:      "a checked module is not",
			unchecked: false,
			wantMark:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := mod(t, "example.com/m", "v1.0.0", "v1.0.0", false)
			m.Unchecked = tc.unchecked

			if tc.wantMark {
				require.Contains(t, m.LabelText(), uncheckedLabel,
					"want an unchecked module marked rather than reading as current")
				return
			}
			require.NotContains(t, m.LabelText(), uncheckedLabel,
				"want no mark on a module that was checked")
		})
	}
}
