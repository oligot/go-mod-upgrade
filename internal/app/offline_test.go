package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClassifyNamesTheCause checks that a per-module failure is sorted into the cause a caller
// can ask errors.Is about, and that the toolchain's own words survive alongside it.
//
// The messages here are the ones the toolchain actually produced, not invented shapes. That
// matters for the GOPROXY=off case in particular: its full text is "module lookup disabled by
// GOPROXY=off", which contains the fragment used to recognise a -mod= refusal. So it stands as
// the case that pins the order the causes are tested in.
func TestClassifyNamesTheCause(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want error
	}{
		{
			name: "a refused connection is an unreachable proxy",
			msg:  `loading module retractions for github.com/alecthomas/kingpin/v2@v2.4.0: Get "https://127.0.0.1:1/mod/github.com/alecthomas/kingpin/v2/@v/list": dial tcp 127.0.0.1:1: connect: connection refused`,
			want: errProxyUnreachable,
		},
		{
			name: "a name that does not resolve is an unreachable proxy",
			msg:  `Get "https://proxy.invalid/mod/rsc.io/quote/@v/list": dial tcp: lookup proxy.invalid: no such host`,
			want: errProxyUnreachable,
		},
		{
			name: "a stalled request is an unreachable proxy",
			msg:  `Get "https://proxy.golang.org/mod/rsc.io/quote/@v/list": net/http: TLS handshake timeout`,
			want: errProxyUnreachable,
		},
		{
			// The real message, which also contains "module lookup disabled" -- so
			// this fails if the causes are tested in the other order.
			name: "GOPROXY=off is the proxy being off, not a -mod refusal",
			msg:  `github.com/spf13/cobra@v1.8.0: module lookup disabled by GOPROXY=off`,
			want: errProxyOff,
		},
		{
			name: "a -mod refusal is a disabled lookup",
			msg:  `module lookup disabled by -mod=vendor`,
			want: errLookupDisabled,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := classify(tc.msg)
			require.ErrorIs(t, err, tc.want)
			// The toolchain said something specific about a specific module, and a
			// reader needs that rather than the category it fell into.
			require.Contains(t, err.Error(), tc.msg,
				"want the toolchain's own message kept alongside the cause")
		})
	}
}

// TestClassifyLeavesAnUnknownFailureAlone checks that a message matching nothing stays a plain
// error rather than being forced into the nearest cause.
//
// A module that genuinely does not exist, or a version never published, is a real answer about
// that module -- not evidence that the network is down. Guessing otherwise would mark a
// mistyped requirement "unknown" and hide it behind a story about connectivity.
func TestClassifyLeavesAnUnknownFailureAlone(t *testing.T) {
	err := classify(`rsc.io/quote@v9.9.9: invalid version: unknown revision v9.9.9`)
	require.Error(t, err)
	for _, cause := range []error{errProxyUnreachable, errProxyOff, errLookupDisabled} {
		require.NotErrorIs(t, err, cause,
			"want an unrecognised failure left as itself, not sorted into a cause")
	}
	require.Contains(t, err.Error(), "unknown revision v9.9.9")
}

// TestReachReadsTheProxy checks how a resolved GOPROXY is read, including the case that reads
// like "nothing" and is not.
//
// An empty GOPROXY falls back to the default proxy rather than disabling lookups, so treating
// empty as offline would mark every module unknown on an ordinary machine.
//
// Through reachFrom rather than by building a reach here: a test that applies the rule itself
// passes whatever the rule does, which is no test of it at all.
func TestReachReadsTheProxy(t *testing.T) {
	tests := []struct {
		name        string
		proxy       string
		wantOffline bool
	}{
		{
			name:        "off disables lookups",
			proxy:       "off",
			wantOffline: true,
		},
		{
			name:        "empty means the default proxy, not none",
			proxy:       "",
			wantOffline: false,
		},
		{
			name:        "a proxy list is reachable",
			proxy:       "https://proxy.golang.org,direct",
			wantOffline: false,
		},
		{
			name:        "direct is reachable, being the network rather than a proxy",
			proxy:       "direct",
			wantOffline: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := reachFrom(tc.proxy)
			require.Equal(t, tc.wantOffline, r.offline())
			require.Equal(t, tc.proxy, r.proxy, "want the resolved value kept for the log")
			if tc.wantOffline {
				require.ErrorIs(t, r.cause, errProxyOff)
			} else {
				require.NoError(t, r.cause)
			}
		})
	}
}

// TestReachOfflineOnlyWhenCaused checks that offline follows the cause rather than the proxy
// string, so an unreachable proxy discovered mid-run counts as offline too.
func TestReachOfflineOnlyWhenCaused(t *testing.T) {
	require.False(t, reach{}.offline(), "want no cause to mean reachable")

	// A proxy that was configured and then could not be reached is offline, even though
	// its GOPROXY says a real address.
	r := reach{proxy: "https://proxy.example", cause: errProxyUnreachable}
	require.True(t, r.offline())
	require.ErrorIs(t, r.cause, errProxyUnreachable)
	require.False(t, errors.Is(r.cause, errProxyOff),
		"want an unreachable proxy distinguished from one switched off")
}
