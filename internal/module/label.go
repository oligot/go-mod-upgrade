package module

import (
	"fmt"
	"strings"
)

// labelSpecs ties each label to the key that selects it, the role colouring it,
// what the legend says about it, and the predicate deciding whether a module
// carries it.
//
// One table rather than four lists. A letter a row prints, a key --labels accepts,
// a legend line and a filter predicate are four views of one fact, and keeping them
// apart is what let the vocabularies drift: the advisories had no letter while C
// already meant cooldown, S and ? were letters no key could select, and ? was a
// letter the legend never explained. Deriving all four here means a label added in
// one place cannot go missing from the others.
//
// Ordered as a row prints them, which mirrors DefaultSorts, so the letters read as
// the priority the listing is ordered by.
var labelSpecs = []struct {
	letter string
	key    string
	role   string
	says   string
	holds  func(Module) bool
}{
	{fixLabel, FilterFixes, RoleFixes,
		"resolves an advisory in another module",
		func(m Module) bool { return m.IsFix() }},
	{vulnReachableLabel, FilterVulnReachable, RoleVulnReachable,
		"this project reaches its vulnerable code",
		func(m Module) bool { return m.VulnCalled() }},
	{vulnPresentLabel, FilterVulnPresent, RoleVuln,
		"carries an advisory whose code this project does not reach",
		func(m Module) bool { return len(m.Vulns) > 0 && !m.VulnCalled() }},
	{indirectLabel, FilterIndirect, RoleIndirect,
		"indirect, reached only through another module",
		func(m Module) bool { return m.Indirect }},
	{cooldownLabel, FilterCooldown, RoleCooldown,
		"released too recently to recommend yet",
		func(m Module) bool { return m.Cooling() }},
	{steppedLabel, FilterStepped, RoleCooldown,
		"still releasing, so its newest settled version is offered",
		func(m Module) bool { return m.Stepped() }},
	{transitiveLabel, FilterTransitive, RoleTransitive,
		"another upgrade already resolves its advisories",
		func(m Module) bool { return m.IsTransitive() }},
	{downgradeLabel, FilterDowngrade, RoleDowngrade,
		"the available version is older than the one installed",
		func(m Module) bool { return m.IsDowngrade() }},
	{deprecatedLabel, FilterDeprecated, RoleDeprecated,
		"deprecated by its author",
		func(m Module) bool { return m.IsDeprecated() }},
	{retractedLabel, FilterRetracted, RoleRetracted,
		"the version in use was withdrawn",
		func(m Module) bool { return m.IsRetracted() }},
	{archivedLabel, FilterArchived, RoleArchived,
		"asserted abandoned by a policy",
		func(m Module) bool { return m.IsArchived() }},
	{uncheckedLabel, FilterUnchecked, RoleUnchecked,
		"no proxy was reachable, so what is available is unknown",
		func(m Module) bool { return m.Unchecked }},
}

// labelSeparator joins expanded label names, which need one where letters do not.
const labelSeparator = ","

// LabelKeys lists the keys naming a label, in the order a row prints them.
//
// Published so help text can show the letter a key selects, the abbreviation being
// no use to a reader who cannot look it up.
func LabelKeys() []string {
	keys := make([]string, 0, len(labelSpecs))
	for _, spec := range labelSpecs {
		keys = append(keys, spec.key)
	}
	return keys
}

// LabelLetter returns the letter a key marks a row with, empty for a key that
// selects rows without marking them.
func LabelLetter(key string) string {
	for _, spec := range labelSpecs {
		if spec.key == key {
			return spec.letter
		}
	}
	return ""
}

// LabelLegend names every key --labels accepts, showing the letter it marks a row
// with where it has one.
//
// A reader meeting "V" in a narrow listing needs to know it is the vuln_reachable
// key before they can ask for only those rows, and help text is where they look.
// Keys with no letter are still listed: they select rows without marking them,
// which is a thing worth asking for and would otherwise be undiscoverable.
func LabelLegend() string {
	parts := make([]string, 0, len(FilterKeys()))
	for _, key := range FilterKeys() {
		if letter := LabelLetter(key); letter != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", key, letter))
			continue
		}
		parts = append(parts, key)
	}
	return strings.Join(parts, ", ")
}
