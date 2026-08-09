package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// scanKey identifies a vulnerability scan by everything that decides its answer.
//
// A scan takes around half a minute on a real tree, so it is worth reusing -- but only when
// reusing it cannot give a different answer than running it. Five things decide that answer:
//
// The requirements, in go.mod and go.sum, which say which versions are scanned.
//
// The project's own source, because govulncheck reports reachability rather than mere
// presence. Adding or deleting a call to a package of an already-required module changes
// whether an advisory is reached while leaving go.mod and go.sum byte-identical -- and
// reachability is what decides whether a policy fails a run or merely warns.
//
// The build tags, since a tag decides which files compile and so which code is reachable.
//
// The advisory database, named by its etag, since a new advisory is a new answer.
//
// The toolchain, since it decides what the standard library contains.
//
// The permitted environment, since it decides what the scan compiles and so what it can
// reach: GOOS and GOARCH select which files build, GOFLAGS can carry -tags, and CGO_ENABLED
// decides whether cgo files are part of the answer at all.
//
// Build artefacts and vendored trees are left out, by the same rule that keeps them out of
// the build-tag search: they are not this project's own source. A vendored dependency is
// scanned as a requirement rather than as source, so its contents reach the answer through
// go.sum.
func scanKey(dir string, tags []string, etag, toolchain string) (string, error) {
	sum := sha256.New()

	// The inputs that are not files, first and in a fixed order. Quoted, since a value
	// holding a newline could otherwise pass itself off as the end of a field and let two
	// different sets of inputs hash alike.
	fmt.Fprintf(sum, "v2\ntoolchain=%q\netag=%q\n", toolchain, etag)
	for _, tag := range tags {
		fmt.Fprintf(sum, "tag=%q\n", tag)
	}
	for _, kv := range keyedEnv() {
		fmt.Fprintf(sum, "env=%q\n", kv)
	}

	// The files, sorted, since a filesystem gives no ordering guarantee and a key that
	// varied with directory order would never hit.
	files, err := scanInputs(dir)
	if err != nil {
		return "", err
	}
	slices.Sort(files)
	for _, at := range files {
		f, err := os.Open(filepath.Join(dir, at))
		if err != nil {
			// A file that cannot be read is one the scan cannot read either, so the
			// key records its absence rather than failing.
			fmt.Fprintf(sum, "file=%q unreadable\n", at)
			continue
		}
		// The path and the length precede the contents, so moving a file changes the key
		// even when its bytes do not, and two files cannot divide the same run of bytes
		// between them differently and still agree. Quoted, so a path holding a newline
		// cannot pass itself off as the end of a field.
		info, err := f.Stat()
		if err != nil {
			if closeErr := f.Close(); closeErr != nil {
				log.Trace().Err(closeErr).Msg("Could not close a file while keying the scan")
			}
			return "", fmt.Errorf("sizing %q: %w", at, err)
		}
		fmt.Fprintf(sum, "file=%q len=%d\n", at, info.Size())
		n, err := io.Copy(sum, f)
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		if err != nil {
			return "", fmt.Errorf("hashing %q: %w", at, err)
		}
		// A file written to between the Stat and the read would leave the length in the
		// key disagreeing with the bytes after it, which is a key nothing can reproduce.
		if n != info.Size() {
			return "", fmt.Errorf("%q changed while being read: %d bytes, expected %d", at, n, info.Size())
		}
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// scanInputs lists the files a scan reads, relative to dir and unsorted.
//
// The requirements and the project's own Go source. Anything skipDir refuses is left out,
// which is what keeps build artefacts and vendored trees from changing the key.
func scanInputs(dir string) ([]string, error) {
	found := []string{"go.mod", "go.sum"}
	err := filepath.WalkDir(dir, func(at string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read holds no source this scan will see
			// either, and is not worth failing over.
			log.Trace().Fields(map[string]any{"path": at, "error": err}).Msg("Skipping an unreadable path while keying the scan")
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) && at != dir {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(at, ".go") {
			return nil
		}
		rel, err := filepath.Rel(dir, at)
		if err != nil {
			return nil
		}
		found = append(found, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error listing the scan's inputs in %q: %w", dir, err)
	}
	return found, nil
}

// scanCacheDir is where scan results live inside the cache directory, beside the
// vulnerability database rather than in the project being scanned: a tool should not leave
// files in a tree it was asked to inspect.
const scanCacheDir = "scans"

// loadScan returns a stored scan result, and whether one was found.
//
// An unreadable entry reads as a miss. A truncated or hand-edited file should cost a rescan
// rather than a crash or, worse, a wrong answer about what is vulnerable.
//
// A hit is touched, because a scan is keyed on the project's sources and so is rewritten only
// when they change. Left alone, the entry for a tree that has stood still for a week would be
// swept while still answering every run.
func loadScan(dir, key string) (vulnerabilities, bool) {
	at := filepath.Join(dir, scanCacheDir, key+".json")
	body, err := os.ReadFile(at)
	if err != nil {
		return nil, false
	}
	var found vulnerabilities
	if err := json.Unmarshal(body, &found); err != nil {
		log.Trace().Fields(map[string]any{"path": at, "error": err}).Msg("Ignoring an unreadable cached scan")
		return nil, false
	}
	if found == nil {
		// A file holding "null" is not a result. An empty scan is stored as {} and
		// unmarshals to an empty map, which is a real answer and must stay one.
		return nil, false
	}
	touch(at)
	return found, true
}

// storeScan records a scan result under its key.
//
// Written to a temporary file and renamed, so a run interrupted mid-write leaves no partial
// entry for the next one to read.
func storeScan(dir, key string, found vulnerabilities) error {
	at := filepath.Join(dir, scanCacheDir)
	if err := os.MkdirAll(at, 0o755); err != nil {
		return fmt.Errorf("error creating %q: %w", at, err)
	}
	// An empty scan is a result rather than an absence, so it is stored as an empty object
	// rather than as null.
	if found == nil {
		found = vulnerabilities{}
	}
	body, err := json.Marshal(found)
	if err != nil {
		return fmt.Errorf("error recording a scan: %w", err)
	}
	tmp, err := os.CreateTemp(at, key+".*")
	if err != nil {
		return fmt.Errorf("error recording a scan: %w", err)
	}
	name := tmp.Name()
	_, err = tmp.Write(body)
	if closeErr := tmp.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		if rmErr := os.Remove(name); rmErr != nil {
			log.Trace().Err(rmErr).Msg("Could not remove a partial scan record")
		}
		return fmt.Errorf("error recording a scan: %w", err)
	}
	return os.Rename(name, filepath.Join(at, key+".json"))
}

// toolchainVersion returns the Go version this process was built with, which decides what the
// standard library contains and so which advisories apply to it.
func toolchainVersion() string { return runtime.Version() }
