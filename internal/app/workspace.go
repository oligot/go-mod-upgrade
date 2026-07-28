package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"golang.org/x/mod/modfile"
)

// workspaceDirs returns the absolute directory of every module named by the
// use directives in the go.work file at gowork.
//
// Paths are resolved against the directory holding the work file rather than
// the working directory, so the tool can be run from anywhere in the
// workspace. See issue https://github.com/oligot/go-mod-upgrade/issues/28
func workspaceDirs(gowork string) ([]string, error) {
	base := filepath.Dir(gowork)

	// Read the work file through a root confined to its own directory, so a
	// symlink in the path cannot lead the read elsewhere.
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	content, err := root.ReadFile(filepath.Base(gowork))
	if closeErr := root.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}

	work, err := modfile.ParseWork(gowork, content, nil)
	if err != nil {
		return nil, fmt.Errorf("error parsing %q: %w", gowork, err)
	}

	var dirs []string
	seen := map[string]bool{}
	for _, use := range work.Use {
		if use == nil {
			continue
		}
		dir := use.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(base, dir)
		}
		dir = filepath.Clean(dir)

		// The same directory can be named by more than one use directive,
		// and processing it twice would offer the same updates twice.
		if seen[dir] {
			log.WithField("dir", dir).Debug("Skipping duplicate workspace module")
			continue
		}
		seen[dir] = true

		// A use directive can outlive the directory it names. Report it and
		// carry on, so the rest of the workspace is still processed.
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			log.WithFields(log.Fields{
				"dir":   dir,
				"error": err,
			}).Warn("Skipping workspace module without a go.mod")
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs, nil
}
