package app

import (
	"bufio"
	"fmt"
	"go/build"
	"go/build/constraint"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
)

// tagFilter is a predicate over build tags: one configuration the project asks to
// be built in.
//
// The default filters are whatever searching the target module turns up, one per
// distinct "//go:build" line, plus the empty predicate a plain build satisfies.
// --tags adjusts or replaces that list.
//
// The predicate is kept rather than only the tags satisfying it, since two
// expressions can want the same tags while meaning different things, and the
// expression is what a listing should name.
type tagFilter struct {
	// expr is the parsed predicate, nil for the default configuration, which is
	// satisfied by setting nothing.
	expr constraint.Expr
	// text is the predicate as written, which is its identity and what a listing
	// shows. Empty for the default configuration.
	text string
}

// String returns how the filter is written, which is the expression it came from
// or "*" for the configuration a plain build sees.
func (f tagFilter) String() string {
	if f.text == "" {
		return defaultTagSet
	}
	return f.text
}

// key identifies the configuration a filter describes, and whether it describes
// one at all.
//
// Two filters share a key when the same tags satisfy both, so "integration &&
// core" and "integration && core && !multinode" are one configuration to analyse.
// An unsatisfiable filter has no key, there being nothing to analyse.
func (f tagFilter) key() (string, bool) {
	tags, ok := f.satisfy()
	if !ok {
		return "", false
	}
	if len(tags) == 0 {
		// Satisfied by setting nothing, which is the default configuration.
		return defaultTagSet, true
	}
	return strings.Join(tags, ","), true
}

// satisfy returns the least tags making the predicate true, and whether it can be
// made true at all by setting tags.
//
// The atoms are few -- a handful per line -- so every subset is tried and the
// smallest satisfying one wins, which is the least a caller would have to pass.
// A predicate satisfied by setting nothing describes the default configuration,
// so it reports no tags rather than failing.
func (f tagFilter) satisfy() (tags []string, ok bool) {
	if f.expr == nil {
		return nil, true
	}

	atoms := map[string]bool{}
	collect(f.expr, atoms)
	// A file no build includes is not a configuration to analyse.
	if atoms[ignoreTag] {
		return nil, false
	}
	var universe []string
	for _, tag := range slices.Sorted(maps.Keys(atoms)) {
		if chosen(tag) {
			universe = append(universe, tag)
		}
	}

	best, found := []string(nil), false
	for mask := range 1 << len(universe) {
		var candidate []string
		on := map[string]bool{}
		for i, tag := range universe {
			if mask&(1<<i) != 0 {
				on[tag] = true
				candidate = append(candidate, tag)
			}
		}
		if !f.expr.Eval(func(tag string) bool { return on[tag] }) {
			continue
		}
		if !found || len(candidate) < len(best) {
			best, found = candidate, true
		}
	}
	return best, found
}

// defaultTagSet names the configuration with no tags set, which is what a plain
// "go build" sees.
//
// "*" rather than a word, since it is not a tag and cannot be confused for one: a
// project may legitimately declare "//go:build default", and a name a constraint
// could also spell would collide with it.
const defaultTagSet = "*"

// ignoreTag is the conventional tag for a file no build should ever include. It
// is excluded rather than solved for, since a file carrying it is not part of any
// configuration the project builds.
const ignoreTag = "ignore"

// chosen reports whether a tag is one a caller could pass with -tags, rather than
// one the toolchain decides for itself.
//
// What the toolchain decides is taken from the toolchain in use and nothing else:
// the GOOS and GOARCH being built for, the releases it satisfies, and whatever it
// was built with. No list of platforms is written down here, and none is
// enumerated -- analysing every port Go supports is not what a project's own
// constraints are about.
//
// So a constraint naming a platform this build is not for, "linux" on a darwin
// machine, is treated as a tag a caller could pass. That is the useful reading:
// the file is part of the project, sweeping with the tag brings it into the
// analysis, and a caller wanting to cover another platform can ask for it
// explicitly. A sweep that changes nothing is dropped when the results are
// deduplicated, so the cost of being wrong here is one wasted pass.
func chosen(tag string) bool {
	switch tag {
	case build.Default.GOOS, build.Default.GOARCH:
		return false
	}
	if slices.Contains(build.Default.ReleaseTags, tag) ||
		slices.Contains(build.Default.ToolTags, tag) {
		return false
	}
	// A release or GOEXPERIMENT beyond the toolchain in use is still the
	// toolchain's to decide, and passing it as a tag would not satisfy it.
	return !strings.HasPrefix(tag, "go1.") && !strings.HasPrefix(tag, "goexperiment.")
}

// discoverFilters returns the build configurations the module in dir declares.
//
// The default configuration comes first, being what a plain build sees. Each
// distinct "//go:build" line in the project's own source contributes one more.
// Two lines wanting the same tags contribute one filter, since scanning the same
// configuration twice would report the same thing twice.
func discoverFilters(dir string) ([]tagFilter, error) {
	exprs, err := constraints(dir)
	if err != nil {
		return nil, err
	}

	filters := []tagFilter{{}}
	seen := map[string]bool{defaultTagSet: true}
	for _, text := range slices.Sorted(maps.Keys(exprs)) {
		f, ok := parseFilter(text)
		if !ok {
			continue
		}
		tags, ok := f.satisfy()
		if !ok || len(tags) == 0 {
			// Unsatisfiable, or satisfied by setting nothing, which the default
			// configuration already covers.
			continue
		}
		key, _ := f.key()
		if seen[key] {
			// "integration && core" and "integration && core && !multinode" both
			// want the same tags, so they describe one configuration to scan.
			continue
		}
		seen[key] = true
		filters = append(filters, f)
	}
	return filters, nil
}

// parseFilter reads one predicate, reporting whether it is usable.
func parseFilter(text string) (tagFilter, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return tagFilter{}, true
	}
	expr, err := constraint.Parse("//go:build " + text)
	if err != nil {
		log.WithFields(log.Fields{
			"constraint": text,
			"error":      err,
		}).Debug("Skipping an unparseable build constraint")
		return tagFilter{}, false
	}
	return tagFilter{expr: expr, text: text}, true
}

// ParseTags reads the --tags value and returns the configurations to scan.
//
// found is what searching the module turned up, which is the default. A value
// with no sign replaces that list outright, so a caller naming a configuration
// scans only that one. A signed value adjusts it: "+expr" adds a configuration,
// and "-expr" drops every discovered one whose tags the expression covers, so
// "-integration" leaves the configurations that do not set it.
//
// Several values may be given, applied in order. Naming the same configuration
// twice asks for it once, since each one costs a full analysis pass.
func ParseTags(specs []string, found []tagFilter) ([]tagFilter, error) {
	var (
		named   []tagFilter
		signed  bool
		filters = slices.Clone(found)
	)
	// Adding a configuration already present would spend a pass to report what
	// the first one reports, so the tags satisfying each are keyed as
	// discoverFilters keys the project's own constraints.
	seen := map[string]bool{}
	for _, f := range filters {
		if key, ok := f.key(); ok {
			seen[key] = true
		}
	}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		add := true
		switch spec[0] {
		case '-':
			add, spec = false, strings.TrimSpace(spec[1:])
		case '+':
			spec = strings.TrimSpace(spec[1:])
		default:
			f, ok := parseFilter(spec)
			if !ok {
				return nil, fmt.Errorf("tags %q: not a build constraint", spec)
			}
			named = append(named, f)
			continue
		}

		signed = true
		if spec == "" {
			// A sign with nothing after it is a typo. Left alone it would parse as
			// the empty predicate, which describes the default configuration, so
			// accepting it would quietly ask for a second default pass.
			return nil, fmt.Errorf("tags: a sign needs a build constraint after it")
		}
		f, ok := parseFilter(spec)
		if !ok {
			return nil, fmt.Errorf("tags %q: not a build constraint", spec)
		}
		if add {
			key, ok := f.key()
			if ok && seen[key] {
				continue
			}
			seen[key] = true
			filters = append(filters, f)
			continue
		}
		// Drop the configurations this predicate describes. A discovered filter
		// goes when its tags satisfy the one being subtracted, which is what
		// makes "-integration" mean "not the integration configurations".
		filters = slices.DeleteFunc(filters, func(have tagFilter) bool {
			tags, ok := have.satisfy()
			if !ok {
				return false
			}
			on := make(map[string]bool, len(tags))
			for _, tag := range tags {
				on[tag] = true
			}
			return f.expr != nil && f.expr.Eval(func(tag string) bool { return on[tag] })
		})
	}

	if len(named) > 0 {
		if signed {
			return nil, fmt.Errorf(
				"tags mixes naming configurations with adjusting them; write either plain constraints or only signed ones")
		}
		return named, nil
	}
	return filters, nil
}

// collect gathers the tag names an expression mentions.
func collect(e constraint.Expr, into map[string]bool) {
	switch x := e.(type) {
	case *constraint.TagExpr:
		into[x.Tag] = true
	case *constraint.NotExpr:
		collect(x.X, into)
	case *constraint.AndExpr:
		collect(x.X, into)
		collect(x.Y, into)
	case *constraint.OrExpr:
		collect(x.X, into)
		collect(x.Y, into)
	}
}

// constraints returns the distinct "//go:build" expressions in the Go files under
// dir, keyed by their text.
//
// Only the project's own source is read: a dependency's constraints are its
// business, and what matters here is which configurations this project asks to be
// built in.
func constraints(dir string) (map[string]bool, error) {
	found := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read tells us nothing about tags, and is
			// not worth failing the run over.
			log.WithFields(log.Fields{
				"path":  path,
				"error": err,
			}).Debug("Skipping an unreadable path while looking for build tags")
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != dir {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		text, err := buildLine(path)
		if err != nil {
			log.WithFields(log.Fields{
				"path":  path,
				"error": err,
			}).Debug("Skipping an unreadable file while looking for build tags")
			return nil
		}
		if text != "" {
			found[text] = true
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error looking for build tags in %q: %w", dir, err)
	}
	return found, nil
}

// skipDir reports whether a directory holds no source of this project's own.
func skipDir(name string) bool {
	switch name {
	case "vendor", "testdata", "node_modules":
		return true
	}
	// Go itself ignores directories beginning with a dot or an underscore, and
	// so should this: .git and .claude hold no buildable source.
	return strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// buildLine returns the "//go:build" expression of a file, empty when it has
// none.
//
// Only the header is read: a constraint has to precede the package clause, so
// there is no reason to scan a whole file.
func buildLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if constraint.IsGoBuild(line) {
			return strings.TrimSpace(strings.TrimPrefix(line, "//go:build")), nil
		}
		// A constraint must appear before the package clause, so once that is
		// reached there is nothing left to find.
		if strings.HasPrefix(line, "package ") {
			return "", nil
		}
	}
	return "", scan.Err()
}
