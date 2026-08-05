package app

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseUpdatesSortsAFailureByItsCause checks what becomes of a module the toolchain reported
// an error for, which depends on whether the error is a definite answer about the module.
//
// Only one case is. A version never published is a real answer, so the module is reported and
// left out; marking it unknown would blame the network for a mistyped requirement. Everything
// else is recorded as unknown, whether the cause was recognised as a reachability failure or not
// recognised at all.
//
// Dropping is not a neutral omission, which is what makes the default matter: assemble reads a
// missing entry as a zero state, which renders as standing at the version in use -- the same row
// a module with nothing newer produces. A tree that could not be checked would read as a clean
// one, which is the wrong answer a pre-commit hook would trust.
func TestParseUpdatesSortsAFailureByItsCause(t *testing.T) {
	tests := []struct {
		name string
		err  string
		// wantRecorded is whether the module survives at all, and wantUnknown whether
		// it is marked as never having been established.
		wantRecorded bool
		wantUnknown  bool
	}{
		{
			name:         "a refused connection is unknown, not current",
			err:          `loading module retractions for example.com/m@v1.0.0: Get "https://127.0.0.1:1/mod/example.com/m/@v/list": dial tcp 127.0.0.1:1: connect: connection refused`,
			wantRecorded: true,
			wantUnknown:  true,
		},
		{
			name:         "a proxy switched off is unknown",
			err:          `example.com/m@v1.0.0: module lookup disabled by GOPROXY=off`,
			wantRecorded: true,
			wantUnknown:  true,
		},
		{
			name:         "a name that does not resolve is unknown",
			err:          `Get "https://proxy.invalid/mod/example.com/m/@v/list": dial tcp: lookup proxy.invalid: no such host`,
			wantRecorded: true,
			wantUnknown:  true,
		},
		{
			// About the module rather than the network, so it is reported and left
			// out rather than quietly recorded as unknown.
			name:         "a version that was never published is not unknown",
			err:          `example.com/m@v9.9.9: invalid version: unknown revision v9.9.9`,
			wantRecorded: false,
		},
		{
			// Neither a transport failure nor an answer about the module. Recorded as
			// unknown, since not knowing why a query failed is not evidence that it
			// succeeded, and a dropped module reads as standing at its current version.
			name:         "a proxy answering 5xx is unknown",
			err:          `example.com/m@v1.0.0: reading https://proxy.example/@v/list: 500 Internal Server Error`,
			wantRecorded: true,
			wantUnknown:  true,
		},
		{
			name:         "a rate limit is unknown",
			err:          `example.com/m@v1.0.0: reading https://proxy.example/@v/list: 429 Too Many Requests`,
			wantRecorded: true,
			wantUnknown:  true,
		},
		{
			name:         "an authentication rejection is unknown",
			err:          `example.com/m@v1.0.0: invalid version: could not read Username: terminal prompts disabled`,
			wantRecorded: true,
			wantUnknown:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Built by marshalling the message rather than by pasting JSON, since
			// these errors carry quotes and backslashes of their own and escaping
			// them by hand is how a fixture comes to test its own escaping.
			out, err := json.Marshal(map[string]any{
				"Path":    "example.com/m",
				"Version": "v1.0.0",
				"Error":   map[string]string{"Err": tc.err},
			})
			require.NoError(t, err)

			found := map[string]state{}
			require.NoError(t, parseUpdates(out, found))

			s, ok := found["example.com/m"]
			require.Equal(t, tc.wantRecorded, ok,
				"want a proxy failure recorded and a module failure reported instead")
			if !tc.wantRecorded {
				return
			}
			require.Equal(t, tc.wantUnknown, s.Unknown)
			require.Empty(t, s.Update, "want no version claimed for a module never asked about")
		})
	}
}

// TestMarkUncheckedOnlyWhenNothingCouldBeLearned checks the gate on marking, which fails in both
// directions and is invisible in the output either way.
//
// Under-marking is the bug this whole flag exists for: an offline run reporting a clean tree.
// Over-marking is the mirror image and no better -- a healthy run marking every module unknown
// tells a reader to distrust an answer that was in fact correct, and a listing where every row
// carries a question mark is one nobody reads.
func TestMarkUncheckedOnlyWhenNothingCouldBeLearned(t *testing.T) {
	tests := []struct {
		name string
		// upgrades is whether -u was passed, and offline whether a proxy was reachable.
		upgrades bool
		offline  bool
		want     bool
	}{
		{
			name:     "offline having asked about upgrades marks them unknown",
			upgrades: true,
			offline:  true,
			want:     true,
		},
		{
			// The case revert-testing exposed as uncovered: online, nothing is
			// unknown, and marking it would be worse than saying nothing.
			name:     "a reachable proxy leaves every module known",
			upgrades: true,
			offline:  false,
			want:     false,
		},
		{
			// Never asked, so the silence is the caller's own doing. This is the
			// ordinary cached path, where -u is deliberately dropped.
			name:     "not having asked about upgrades is not the same as not knowing",
			upgrades: false,
			offline:  true,
			want:     false,
		},
		{
			name:     "neither asked nor offline",
			upgrades: false,
			offline:  false,
			want:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := map[string]state{
				"example.com/m": {Update: "v1.2.0", Deprecated: "gone"},
			}
			r := reach{}
			if tc.offline {
				r = reachFrom(goproxyOff)
			}

			markUnchecked(found, tc.upgrades, r)

			s := found["example.com/m"]
			require.Equal(t, tc.want, s.Unknown)
			if tc.want {
				require.Empty(t, s.Update,
					"want an upgrade withdrawn, no offline query having offered one")
			} else {
				require.Equal(t, "v1.2.0", s.Update, "want a real answer left alone")
			}
			// What came from the module cache is true either way, so it survives
			// being marked unknown.
			require.Equal(t, "gone", s.Deprecated,
				"want the module cache's own facts kept regardless")
		})
	}
}

// TestParseUpdatesLeavesAReachableModuleAlone checks that the ordinary case is untouched: a
// module the proxy answered about is not unknown, whether or not it had an upgrade.
//
// The second case is the one that must stay distinguishable from unknown, since the two render
// identically once the flag is lost.
func TestParseUpdatesLeavesAReachableModuleAlone(t *testing.T) {
	tests := []struct {
		name       string
		out        string
		wantUpdate string
	}{
		{
			name:       "an upgrade is available",
			out:        `{"Path":"example.com/m","Version":"v1.0.0","Update":{"Version":"v1.2.0"}}`,
			wantUpdate: "v1.2.0",
		},
		{
			name:       "the module is already current",
			out:        `{"Path":"example.com/m","Version":"v1.0.0"}`,
			wantUpdate: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			found := map[string]state{}
			require.NoError(t, parseUpdates([]byte(tc.out), found))

			s := found["example.com/m"]
			require.False(t, s.Unknown, "want a module the proxy answered about left known")
			require.Equal(t, tc.wantUpdate, s.Update)
		})
	}
}
