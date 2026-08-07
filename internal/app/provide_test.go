package app

import (
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/stretchr/testify/require"
)

// TestShowingAdvisoriesNamesWhatTheScanFound pins that a found advisory gets a column
// to be named in, and that saying otherwise outranks it.
//
// The default selects on reached advisories and DefaultColumns has no ADVISORY column,
// so a default run would print the letter standing for an advisory with no identifier
// beside it -- having already paid the scan that knows it.
func TestShowingAdvisoriesNamesWhatTheScanFound(t *testing.T) {
	one := vulnerabilities{"example.com/m": {{ID: "CVE-0000-0001"}}}

	tests := []struct {
		name string
		// spec is the --columns value, empty meaning the default.
		spec  string
		found vulnerabilities
		want  bool
	}{{
		// The case this exists for: the default names no ADVISORY column.
		name:  "a found advisory is given a column",
		found: one,
		want:  true,
	}, {
		// A clean project keeps the columns it asked for.
		name:  "finding nothing adds nothing",
		found: vulnerabilities{},
		want:  false,
	}, {
		// Naming the columns outright is speaking about all of them.
		name:  "naming the columns outright wins",
		spec:  "name,from,to",
		found: one,
		want:  false,
	}, {
		// Excluding the column is asking for it gone.
		name:  "excluding the column wins",
		spec:  "-vuln",
		found: one,
		want:  false,
	}, {
		// Asking for it and finding one is not a reason to drop it.
		name:  "asking for it keeps it",
		spec:  "+vuln",
		found: one,
		want:  true,
	}}

	app := &AppEnv{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			columns, err := module.ParseColumns(tc.spec, app.columnBase())
			require.NoError(t, err)
			require.Equal(t, tc.want,
				showingAdvisories(columns, tc.found).Has(module.ColumnVuln),
				"columns=%q with %d advisories", tc.spec, len(tc.found))
		})
	}
}

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

// TestListingFollowsTheOutputUnlessNamed pins the three states of --list.
//
// Nothing said is not false: a run whose output is redirected is read by something,
// and prompting a program that cannot answer would hang it. So unset follows the
// output, which is what the pointer records and a plain bool could not -- a caller
// asking for exactly the built-in default is otherwise indistinguishable from one
// who said nothing.
func TestListingFollowsTheOutputUnlessNamed(t *testing.T) {
	tests := []struct {
		name string
		app  AppEnv
		want bool
	}{{
		// --non-interactive settles interactivity, so nothing said means a listing.
		name: "unset without a person to ask lists",
		app:  AppEnv{NonInteractive: true},
		want: true,
	}, {
		// The case the tri-state exists for: --no-list is not the unset state, so a
		// redirected run can still upgrade.
		name: "declined outright does not list",
		app:  AppEnv{NonInteractive: true, List: new(false)},
		want: false,
	}, {
		name: "asked for outright lists",
		app:  AppEnv{NonInteractive: true, List: new(true)},
		want: true,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.app.listing())
		})
	}
}

// TestListingAndInteractivityAreOrthogonal pins that --list and --non-interactive
// decide different things.
//
// --non-interactive says there is nobody to prompt; --list says to write a listing
// rather than apply anything. Deriving one from the other would leave a plain
// "go-mod-upgrade --list | awk" run treated as interactive.
func TestListingAndInteractivityAreOrthogonal(t *testing.T) {
	// Asking for a listing says nothing about whether a person is there to read it.
	asked := AppEnv{List: new(true)}
	require.True(t, asked.listing())

	// And declining to prompt says nothing about whether a listing is wanted: the
	// upgrade path is still reachable without a person.
	quiet := AppEnv{NonInteractive: true, List: new(false)}
	require.False(t, quiet.listing())
	require.False(t, quiet.interactive())
}

// TestHeadersAndTokensFollowInteractivity pins that both derive from one fact rather
// than carrying flags of their own.
//
// A heading helps a person and hinders a parser, so it follows interactivity when
// nothing was said. --non-interactive settles that, which is what makes the derived
// answers agree with each other.
func TestHeadersAndTokensFollowInteractivity(t *testing.T) {
	tests := []struct {
		name    string
		app     AppEnv
		headers bool
	}{{
		// Nothing said and nobody to ask: no heading.
		name: "unset without a person to ask",
		app:  AppEnv{NonInteractive: true},
	}, {
		// Saying so outright settles it, whatever the output is.
		name:    "asked for outright",
		app:     AppEnv{NonInteractive: true, Headers: new(true)},
		headers: true,
	}, {
		name: "declined outright",
		app:  AppEnv{NonInteractive: true, Headers: new(false)},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.headers, tc.app.showHeaders())
		})
	}
}
