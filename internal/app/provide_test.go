package app

import (
	"testing"

	"github.com/oligot/go-mod-upgrade/internal/module"
	"github.com/oligot/go-mod-upgrade/internal/policy"
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
	}, {
		// Intersecting a key is still asking about it. The work a term demands is the
		// union of what its keys demand, since a row cannot be tested against a
		// property nothing gathered.
		name:   "intersecting an advisory pays for the scan",
		labels: "vuln&delta",
		want:   []string{module.ColumnVuln},
	}, {
		// Both halves of an intersection are demanded, each answered by different work.
		name:   "an intersection pays for every key it names",
		labels: "vuln&fixes",
		want:   []string{module.ColumnVuln, module.ColumnHint},
	}, {
		// Excluding an intersection needs both answers too, for the same reason
		// excluding a single key does.
		name:   "excluding an intersection still pays for its keys",
		labels: "-vuln_reachable&delta",
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

// A policy that judges the run on what the scan finds.
const judgingAdvisories = `{
  "actions": {"fail": {"exit": 1}},
  "modules": {"**": {"allow": "*"}},
  "rules":   [{"when": "vuln_reachable", "then": "fail"}]
}`

// A policy about versions alone, which needs no scan to apply.
const judgingVersions = `{
  "actions": {"fail": {"exit": 1}},
  "modules": {"**": {"allow": ">= v1.0.0"}},
  "rules":   [{"when": "version-denied", "then": "fail"}]
}`

// TestDemandsReadsWhatThePolicyAsksAbout pins that a policy judging a run on
// advisories pays for the scan, whatever the flags said, and that one about versions
// alone does not.
//
// The demand cannot be read off the columns. A policy loads after the columns are
// resolved and widens them through Columns.With, which adds nothing to a chain that
// named its columns outright nor one that excluded that column -- so a caller passing
// --columns=-vuln leaves v.columns with no record that the scan is needed. Were the
// demand taken from there, the policy would judge every module against a field
// nothing filled, and a reachable advisory would pass as a clean tree. Reading the
// rules is what keeps the question and the work that answers it together.
func TestDemandsReadsWhatThePolicyAsksAbout(t *testing.T) {
	tests := []struct {
		name string
		// body is the policy JSON, empty meaning no policy was given.
		body string
		// labels and columns are the flag values; the labels here name no key that
		// reads the scan, so the policy is the only thing that can demand it.
		labels  string
		columns string
		want    bool
	}{{
		// The case this arm exists for: nothing in the flags asks about advisories.
		name:   "a policy asking about advisories pays for the scan",
		body:   judgingAdvisories,
		labels: "direct",
		want:   true,
	}, {
		// Excluding the column hides the finding; it does not withdraw the policy's
		// question. With is a no-op on this chain, so v.columns knows nothing here.
		name:    "excluding the column does not excuse the scan",
		body:    judgingAdvisories,
		labels:  "direct",
		columns: "-vuln",
		want:    true,
	}, {
		// An exact chain is the other shape With declines to widen.
		name:    "naming the columns outright does not excuse the scan",
		body:    judgingAdvisories,
		labels:  "direct",
		columns: "name,from,to",
		want:    true,
	}, {
		// A policy is not a blanket reason to scan: only one reading advisories is.
		name:   "a policy about versions alone pays for no scan",
		body:   judgingVersions,
		labels: "direct",
		want:   false,
	}, {
		// The nil case, no policy having been given.
		name:   "no policy pays for no scan",
		labels: "direct",
		want:   false,
	}}

	app := &AppEnv{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := module.ParseFilter(tc.labels, app.filterBase())
			require.NoError(t, err)
			columns, err := module.ParseColumns(tc.columns, app.columnBase())
			require.NoError(t, err)

			var rules *policy.Policy
			if tc.body != "" {
				rules = gate(t, tc.body)
			}

			got := app.demands(view{filter: filter, columns: columns, rules: rules})
			require.Equal(t, tc.want, got.Has(module.ColumnVuln),
				"labels=%q columns=%q demands %q: %v",
				tc.labels, tc.columns, module.ColumnVuln, got.Ordered())
		})
	}
}

// TestScopeFollowsWhatTheLabelsAskAbout pins how far discovery reads for a given
// chain of labels.
//
// Selecting on a property nothing gathered lists nothing, and indirect requirements
// are dropped before any version is queried unless the scope widens. That is why the
// default listing was empty on a workspace whose every upgradable module was indirect:
// not a filter withholding rows, but discovery never reading them. Only a key asking
// to keep rows widens -- excluding a category yields the same listing whether a row
// was discovered and dropped or never discovered at all.
func TestScopeFollowsWhatTheLabelsAskAbout(t *testing.T) {
	tests := []struct {
		name   string
		labels string
		format string
		want   scope
	}{{
		// The default asks about indirect requirements, which is what makes an
		// upgrade to one discoverable.
		name: "the default reads indirect requirements",
		want: scopeIndirect,
	}, {
		// Naming a set outright drops the default, so a chain about direct modules
		// reads no further than them.
		name:   "naming the direct key alone stays narrow",
		labels: "direct",
		want:   scopeDirect,
	}, {
		// Intersecting the key is still asking about it, so it widens as naming it does.
		name:   "intersecting the indirect key widens",
		labels: "indirect&delta",
		want:   scopeIndirect,
	}, {
		// Excluding needs no wider search: the listing is the same either way.
		name:   "excluding the indirect key does not widen",
		labels: "+all,-indirect",
		want:   scopeAll,
	}, {
		name:   "dropping indirect from the default stays narrow",
		labels: "-indirect",
		want:   scopeDirect,
	}, {
		// A policy's module map means nothing against a partial build list.
		name:   "a policy reads everything",
		format: module.FormatPolicy,
		want:   scopeAll,
	}, {
		name:   "the all key reads everything",
		labels: "all",
		want:   scopeAll,
	}}

	app := &AppEnv{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := module.ParseFilter(tc.labels, app.filterBase())
			require.NoError(t, err)
			format := tc.format
			if format == "" {
				format = module.FormatHuman
			}
			require.Equal(t, tc.want, app.scope(filter, format),
				"labels=%q format=%q", tc.labels, format)
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

// TestEveryColumnDeclaresItsWork pins that fillings answers for every column, which
// is what fill's unknown-column arm says makes it unreachable.
//
// A column with no entry renders empty rather than ending the run, so nothing at
// runtime says a column was forgotten -- the listing simply has a blank column in it.
// The registry is where whether work happens is decided, so a column reaching the
// display without one is a question asked that nothing answered.
//
// Checked against ColumnNames, the accepted keys, rather than against a list written
// here: a list of its own would be a second registry to forget to update, and the
// point is that adding a column fails this test until it declares what it takes.
func TestEveryColumnDeclaresItsWork(t *testing.T) {
	declared := fillings()
	for _, column := range module.ColumnNames() {
		f, ok := declared[column]
		require.True(t, ok,
			"column %q declares no filling, so nothing gathers what it shows", column)
		// A paid entry names the work; a free one is filled by discovery and must not,
		// since an entry with a cost and nothing to run would pay for a no-op.
		if f.cost == paid {
			require.NotNil(t, f.provide, "column %q is paid but names no work", column)
		} else {
			require.Nil(t, f.provide, "column %q is free but names work to do", column)
		}
	}
	// The other direction: an entry for a key no column names is work that cannot be
	// demanded, since demands only ever asks about accepted keys.
	for column := range declared {
		require.Contains(t, module.ColumnNames(), column,
			"filling %q answers for no column", column)
	}
}
