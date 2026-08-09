package app

import (
	"bufio"
	"cmp"
	"fmt"
	"go/build"
	"go/build/constraint"
	"io/fs"
	"maps"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// tagSet is a set of build tags: those an expression mentions, or those one
// configuration sets. A tag is present or it is not, which is the whole of its
// state.
type tagSet map[string]struct{}

// add records a tag.
func (s tagSet) add(tag string) { s[tag] = struct{}{} }

// isSet reports whether a tag is in the set, and is what a predicate is evaluated
// against: constraint.Expr.Eval takes exactly this shape.
func (s tagSet) isSet(tag string) bool {
	_, ok := s[tag]
	return ok
}

// covers reports whether the set holds every tag another configuration needs.
func (s tagSet) covers(needs []string) bool {
	for _, tag := range needs {
		if !s.isSet(tag) {
			return false
		}
	}
	return true
}

// tagFilter is one configuration to analyse: an assignment of build tags the
// project asks to be built under.
//
// The default filters are whatever searching the target module turns up -- one per
// build each distinct "//go:build" line describes -- plus the plain build, which
// sets nothing. --tags adjusts or replaces that list.
//
// A predicate describing several builds contributes one filter each, since a
// filter is one pass of the toolchain. Siblings share the predicate they came
// from and differ in the tags they set, which is what tells them apart.
type tagFilter struct {
	// expr is the predicate this configuration satisfies, nil for the plain build.
	// Kept for --tags, which subtracts by evaluating a predicate over the tags.
	expr constraint.Expr
	// text is that predicate as written. Several configurations can come from one
	// line, and which line is worth saying in a log.
	text string
	// tags are the tags this configuration sets, sorted. Empty for the plain build.
	tags []string
}

// String names the configuration by the tags it sets, or "*" for the plain build,
// which sets none.
//
// A conjunction rather than a comma-separated list, so that the name is itself a
// build constraint: --tags takes "//go:build" syntax, in which a comma means
// nothing, and a name a reader cannot pass back is one they will mistype.
func (f tagFilter) String() string {
	if len(f.tags) == 0 {
		return defaultTagSet
	}
	return strings.Join(f.tags, " && ")
}

// branches returns one configuration per build a predicate describes, and none
// when it describes no build of its own -- unsatisfiable, or satisfied by setting
// nothing, which the plain build already covers.
//
// Two configurations setting the same tags are one configuration, so a predicate
// yields no duplicates: "integration && core" and "integration && core &&
// !multinode" both describe the one build.
func branches(text string, expr constraint.Expr) []tagFilter {
	sets, ok := assignments(expr)
	if !ok {
		return nil
	}
	text = strings.TrimSpace(text)
	out := make([]tagFilter, 0, len(sets))
	for _, tags := range sets {
		if len(tags) == 0 {
			// Satisfied by setting nothing, which the plain build already covers.
			continue
		}
		out = append(out, tagFilter{expr: expr, text: text, tags: tags})
	}
	return out
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
// The plain build comes first, being what a plain "go build" sees. Each distinct
// "//go:build" line in the project's own source contributes one configuration per
// build it describes, so a line naming an or-group contributes one per arm.
//
// Two configurations setting the same tags contribute one filter, whether they came
// from one line or several: analysing the same build twice would report the same
// thing twice.
func discoverFilters(dir string) ([]tagFilter, error) {
	exprs, err := constraints(dir)
	if err != nil {
		return nil, err
	}

	filters := []tagFilter{{}}
	seen := tagSet{defaultTagSet: struct{}{}}
	for _, text := range slices.Sorted(maps.Keys(exprs)) {
		expr, ok := parseExpr(text)
		if !ok {
			continue
		}
		for _, f := range branches(text, expr) {
			if seen.isSet(f.String()) {
				continue
			}
			seen.add(f.String())
			filters = append(filters, f)
		}
	}
	return filters, nil
}

// assignments returns every minimal way to satisfy a predicate by setting tags,
// and whether it can be satisfied at all.
//
// Minimal by inclusion rather than by size: "core || (opensearchtransport &&
// multinode)" is satisfied irredundantly two ways, and keeping only the smallest
// would drop the arm costing more tags -- which is the build whose modules go
// uninspected. So a satisfying set is kept unless another kept set is contained in
// it, which is what makes each one a distinct build rather than a superset of one.
//
// Every one is reported. A predicate satisfiable ten ways costs ten analysis
// passes, which is the honest price of covering ten builds: analysing some of them
// and reporting the result as a clean tree would be the failure this exists to
// prevent.
//
// A predicate satisfied by setting nothing reports one empty assignment: that is
// the plain build, which is a configuration, unlike an unsatisfiable predicate
// which is none.
func assignments(expr constraint.Expr) (sets [][]string, ok bool) {
	if expr == nil {
		return [][]string{{}}, true
	}

	atoms := tagSet{}
	collect(expr, atoms)
	// A file no build includes is not a configuration to analyse.
	if atoms.isSet(ignoreTag) {
		return nil, false
	}
	var universe []string
	for _, tag := range slices.Sorted(maps.Keys(atoms)) {
		if chosen(tag) {
			universe = append(universe, tag)
		}
	}

	// Fewest tags first, so a set is only ever tested against the sets already
	// kept, which are the only ones that could be contained in it.
	var kept [][]string
	for size := 0; size <= len(universe); size++ {
		for mask := range 1 << len(universe) {
			if bits.OnesCount(uint(mask)) != size {
				continue
			}
			var candidate []string
			on := tagSet{}
			for i, tag := range universe {
				if mask&(1<<i) != 0 {
					on.add(tag)
					candidate = append(candidate, tag)
				}
			}
			if !expr.Eval(on.isSet) {
				continue
			}
			if slices.ContainsFunc(kept, on.covers) {
				// Setting more than another assignment needs describes the same
				// build with tags added, not a build of its own.
				continue
			}
			kept = append(kept, candidate)
		}
	}
	if len(kept) == 0 {
		return nil, false
	}
	return kept, true
}

// compareExpr orders two predicates by their shape, so that a set of them has a
// decided order rather than the order they were discovered in.
//
// The tree decides rather than the rendered text, which would sort by how a
// constraint happened to be written: "(a && b)" precedes "a" on the parenthesis,
// though the parenthesis is not part of the predicate. Shape first -- a tag, then a
// negation, then a conjunction, then a disjunction -- and within one shape the
// operands, left to right.
//
// A nil predicate is the plain build, which sets nothing and so leads.
func compareExpr(a, b constraint.Expr) int {
	if a == nil || b == nil {
		return cmp.Compare(rank(a), rank(b))
	}
	if c := cmp.Compare(rank(a), rank(b)); c != 0 {
		return c
	}
	switch x := a.(type) {
	case *constraint.TagExpr:
		return cmp.Compare(x.Tag, b.(*constraint.TagExpr).Tag)
	case *constraint.NotExpr:
		return compareExpr(x.X, b.(*constraint.NotExpr).X)
	case *constraint.AndExpr:
		y := b.(*constraint.AndExpr)
		if c := compareExpr(x.X, y.X); c != 0 {
			return c
		}
		return compareExpr(x.Y, y.Y)
	case *constraint.OrExpr:
		y := b.(*constraint.OrExpr)
		if c := compareExpr(x.X, y.X); c != 0 {
			return c
		}
		return compareExpr(x.Y, y.Y)
	}
	return 0
}

// rank orders the shapes a predicate can take, simplest first.
func rank(e constraint.Expr) int {
	switch e.(type) {
	case nil:
		return 0
	case *constraint.TagExpr:
		return 1
	case *constraint.NotExpr:
		return 2
	case *constraint.AndExpr:
		return 3
	case *constraint.OrExpr:
		return 4
	}
	return 5
}

// parseExpr reads one predicate, reporting whether it is usable. A nil expression
// is the empty predicate, which the plain build satisfies.
func parseExpr(text string) (constraint.Expr, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, true
	}
	expr, err := constraint.Parse("//go:build " + text)
	if err != nil {
		log.Trace().Fields(map[string]any{
			"constraint": text,
			"error":      err,
		}).Msg("Skipping an unparseable build constraint")
		return nil, false
	}
	return expr, true
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
	// Adding a configuration already present would spend a pass to report what the
	// first one reports, so configurations are keyed by name as discoverFilters
	// keys the project's own constraints.
	seen := tagSet{}
	for _, f := range filters {
		seen.add(f.String())
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
			expr, ok := parseExpr(spec)
			if !ok {
				return nil, fmt.Errorf("tags %q: not a build constraint", spec)
			}
			// Naming one configuration twice asks for it once, whether it was
			// spelled the same way both times or not.
			for _, f := range branches(spec, expr) {
				if slices.ContainsFunc(named, func(had tagFilter) bool {
					return had.String() == f.String()
				}) {
					continue
				}
				named = append(named, f)
			}
			continue
		}

		signed = true
		if spec == "" {
			// A sign with nothing after it is a typo. Left alone it would parse as
			// the empty predicate, which describes the default configuration, so
			// accepting it would quietly ask for a second default pass.
			return nil, fmt.Errorf("tags: a sign needs a build constraint after it")
		}
		expr, ok := parseExpr(spec)
		if !ok {
			return nil, fmt.Errorf("tags %q: not a build constraint", spec)
		}
		if add {
			for _, f := range branches(spec, expr) {
				if seen.isSet(f.String()) {
					continue
				}
				seen.add(f.String())
				filters = append(filters, f)
			}
			continue
		}
		// Drop the configurations this predicate describes. A discovered filter
		// goes when its tags satisfy the one being subtracted, which is what
		// makes "-integration" mean "not the integration configurations".
		filters = slices.DeleteFunc(filters, func(have tagFilter) bool {
			on := make(tagSet, len(have.tags))
			for _, tag := range have.tags {
				on.add(tag)
			}
			return expr != nil && expr.Eval(on.isSet)
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
func collect(e constraint.Expr, into tagSet) {
	switch x := e.(type) {
	case *constraint.TagExpr:
		into.add(x.Tag)
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
			log.Trace().Fields(map[string]any{
				"path":  path,
				"error": err,
			}).Msg("Skipping an unreadable path while looking for build tags")
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
			log.Trace().Fields(map[string]any{
				"path":  path,
				"error": err,
			}).Msg("Skipping an unreadable file while looking for build tags")
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
