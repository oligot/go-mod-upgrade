package app

import (
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/stretchr/testify/require"
)

// TestDemandsCoversWhatTheSelectorsRead pins that a run gathers exactly what the
// selectors ask about, and that the default is what asks for the scan.
//
// The default keeps the modules whose vulnerable code is reached, so a default run
// has to find out which those are: were the scan skipped, the key would select on a
// field nothing filled and a vulnerable tree would list as a clean one. This is the
// case the demand set exists for, and it is a key with no column of its own in
// DefaultColumns -- so nothing else in a default listing would trigger the work.
func TestDemandsCoversWhatTheSelectorsRead(t *testing.T) {
	tests := []struct {
		name string
		// labels and columns are the flag values, empty meaning the default.
		labels  string
		columns string
		// want names the columns whose work the run must do; absent names the ones
		// it must not pay for.
		want   []string
		absent []string
	}{{
		// Ruling D: the default demands the scan, having a key that reads it.
		name: "the default pays for the scan",
		want: []string{module.ColumnVuln},
		// Not the resolvers pass: no default key reads what it attaches.
		absent: []string{module.ColumnHint},
	}, {
		// Both senses ask the scan the same question.
		name:   "selecting on an unreached advisory pays for the scan",
		labels: "vuln_present",
		want:   []string{module.ColumnVuln},
	}, {
		// The alias resolves before the lookup, so the short spelling demands what
		// the long one does.
		name:   "the alias demands what it abbreviates",
		labels: "vuln",
		want:   []string{module.ColumnVuln},
	}, {
		// Naming a set outright drops the default, and with it the scan.
		name:   "naming a set without an advisory key pays for no scan",
		labels: "direct",
		absent: []string{module.ColumnVuln, module.ColumnHint},
	}, {
		// A displayed column is a question too, so asking to see it does the work.
		name:    "asking to display a column pays for it",
		labels:  "direct",
		columns: "+hint",
		want:    []string{module.ColumnHint},
	}, {
		// Excluding still needs the answer: knowing which rows to hide is the same
		// lookup as knowing which to show.
		name:   "excluding an advisory still pays for the scan",
		labels: "-vuln_reachable",
		want:   []string{module.ColumnVuln},
	}}

	app := &AppEnv{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := module.ParseFilter(tc.labels, app.filterBase())
			require.NoError(t, err)
			columns, err := module.ParseColumns(tc.columns, app.columnBase())
			require.NoError(t, err)

			got := app.demands(view{filter: filter, columns: columns})
			for _, column := range tc.want {
				require.True(t, got.Has(column),
					"labels=%q columns=%q demands no %q", tc.labels, tc.columns, column)
			}
			for _, column := range tc.absent {
				require.False(t, got.Has(column),
					"labels=%q columns=%q pays for %q, which nothing reads",
					tc.labels, tc.columns, column)
			}
		})
	}
}
