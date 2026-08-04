package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRejectArgs checks that positional arguments are refused rather than ignored.
//
// The command takes none, and silently discarding them is what made
// "go-mod-upgrade example.com/m" read as a request to upgrade one module while it
// upgraded every one.
func TestRejectArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "none",
			args: nil,
		},
		{
			name: "empty rather than nil",
			args: []string{},
		},
		{
			name: "a module path",
			args: []string{"example.com/my/module"},
			want: `unexpected argument "example.com/my/module"`,
		},
		{
			// Only the first is named: a caller who passed four has the same thing to
			// fix as one who passed one.
			name: "several",
			args: []string{"example.com/first", "example.com/second"},
			want: `unexpected argument "example.com/first"`,
		},
		{
			// An empty argument is still an argument -- "go-mod-upgrade ''" passed one --
			// so it is named rather than read as none.
			name: "an empty string",
			args: []string{""},
			want: `unexpected argument ""`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectArgs(tc.args)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.want)
		})
	}
}
