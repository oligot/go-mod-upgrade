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

// tagSet is one build configuration to analyse: the tags that have to be set for
// a group of constrained files to compile.
//
// The empty set is always analysed, since it is what a plain build sees. Every
// other set comes from a "//go:build" line in the project's own source.
type tagSet struct {
	// Tags are the tags to pass to the toolchain, sorted so a set has one name.
	Tags []string
	// From is the constraint expression this set satisfies, empty for the
	// default configuration. It is what a listing names, since "integration &&
	// (core || opensearchapi)" says more than the tags solving it.
	From string
}

// Name returns how the set is written in a listing, and is what two identical
// sets compare equal on.
func (t tagSet) Name() string {
	if len(t.Tags) == 0 {
		return defaultTagSet
	}
	return strings.Join(t.Tags, ",")
}

// defaultTagSet names the configuration with no tags set, which is what a plain
// "go build" sees.
const defaultTagSet = "default"

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

// tagSets returns the build configurations to analyse for the module in dir.
//
// The default configuration always comes first. Each distinct "//go:build" line
// in the project's own source contributes one more, named for the expression and
// carrying a minimal set of tags satisfying it -- so a project whose tests hide
// behind "integration" is analysed both ways rather than only as a plain build
// sees it.
func tagSets(dir string) ([]tagSet, error) {
	exprs, err := constraints(dir)
	if err != nil {
		return nil, err
	}

	sets := []tagSet{{}}
	seen := map[string]bool{defaultTagSet: true}
	for _, text := range slices.Sorted(maps.Keys(exprs)) {
		set, ok := solve(text)
		if !ok {
			continue
		}
		set.From = text
		if seen[set.Name()] {
			// Two expressions can want the same tags: "integration && core" and
			// "integration && core && !multinode" both solve to the same set.
			continue
		}
		seen[set.Name()] = true
		sets = append(sets, set)
	}
	return sets, nil
}

// solve returns a minimal set of tags satisfying an expression.
//
// The atoms are few -- a handful per line -- so every subset is tried, smallest
// first, which yields the least a caller would have to pass. An expression
// satisfied with no tags at all describes the default configuration and needs no
// set of its own.
func solve(text string) (tagSet, bool) {
	expr, err := constraint.Parse("//go:build " + text)
	if err != nil {
		log.WithFields(log.Fields{
			"constraint": text,
			"error":      err,
		}).Debug("Skipping an unparseable build constraint")
		return tagSet{}, false
	}

	atoms := map[string]bool{}
	collect(expr, atoms)
	// A file no build includes is not a configuration to analyse.
	if atoms[ignoreTag] {
		return tagSet{}, false
	}
	var universe []string
	for _, tag := range slices.Sorted(maps.Keys(atoms)) {
		if chosen(tag) {
			universe = append(universe, tag)
		}
	}
	if len(universe) == 0 {
		// Only platform tags, which the toolchain decides rather than a caller.
		return tagSet{}, false
	}

	// Smallest satisfying subset wins, so a caller is told the least it needs.
	best, found := []string(nil), false
	for mask := range 1 << len(universe) {
		var tags []string
		on := map[string]bool{}
		for i, tag := range universe {
			if mask&(1<<i) != 0 {
				on[tag] = true
				tags = append(tags, tag)
			}
		}
		if !expr.Eval(func(tag string) bool { return on[tag] }) {
			continue
		}
		if !found || len(tags) < len(best) {
			best, found = tags, true
		}
	}
	if !found || len(best) == 0 {
		// Satisfied by setting nothing, which is the default configuration.
		return tagSet{}, false
	}
	return tagSet{Tags: best}, true
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
