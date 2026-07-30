package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// pkg mirrors the parts of "go list -json" that we read.
type pkg struct {
	ImportPath string
	Module     *struct {
		Path string
		Main bool
	}
	Imports      []string
	TestImports  []string
	XTestImports []string
}

// dependents maps a module path to the paths of the modules that import it.
type dependents map[string][]string

// reverseDeps reports, for every module contributing packages to the build in
// dir under one configuration, which other modules import it. It answers how much
// of the build a given upgrade reaches.
func reverseDeps(ctx context.Context, dir string, f tagFilter) (dependents, error) {
	args := []string{"list", "-e", "-deps", "-test", "-json"}
	args = append(args, f.tagArgs()...)
	args = append(args, "./...")
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	// -e is what makes this usable: a package that cannot be loaded is
	// reported in place rather than emptying the whole listing, which happens
	// in a module needing a GOEXPERIMENT the toolchain was not asked for.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running go command to inspect dependencies: %w", err)
	}
	return parseReverseDeps(out)
}

// parseReverseDeps folds the package import graph in the output of
// "go list -json" into a module-level one.
func parseReverseDeps(out []byte) (dependents, error) {
	var pkgs []pkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("error parsing go list output: %w", err)
		}
		pkgs = append(pkgs, p)
	}

	// Imports name packages, so they have to be resolved to the module
	// providing them before the edges mean anything at module level.
	owner := make(map[string]string, len(pkgs))
	main := map[string]bool{}
	for _, p := range pkgs {
		if p.Module == nil {
			// A standard library package belongs to no module.
			continue
		}
		owner[p.ImportPath] = p.Module.Path
		if p.Module.Main {
			main[p.Module.Path] = true
		}
	}

	seen := map[string]map[string]bool{}
	for _, p := range pkgs {
		if p.Module == nil {
			continue
		}
		from := p.Module.Path
		for _, imports := range [][]string{p.Imports, p.TestImports, p.XTestImports} {
			for _, i := range imports {
				to, ok := owner[i]
				// A module importing itself says nothing about its own reach.
				if !ok || to == from {
					continue
				}
				if seen[to] == nil {
					seen[to] = map[string]bool{}
				}
				seen[to][from] = true
			}
		}
	}

	deps := dependents{}
	for to, froms := range seen {
		list := make([]string, 0, len(froms))
		for from := range froms {
			list = append(list, from)
		}
		// The modules being worked on come first, then the rest by name, so
		// that the entries surviving truncation are the informative ones.
		slices.SortFunc(list, func(a, b string) int {
			if main[a] != main[b] {
				if main[a] {
					return -1
				}
				return 1
			}
			return strings.Compare(a, b)
		})
		deps[to] = list
	}
	return deps, nil
}
