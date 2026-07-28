package app

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/google/renameio/v2"
)

const (
	// vulndbURL is the bulk download of the Go vulnerability database. Fetching
	// it as one archive avoids a request per advisory.
	vulndbURL = "https://vuln.go.dev/vulndb.zip"

	// cacheEnv overrides where the database is cached.
	cacheEnv = "GO_MOD_UPGRADE_CACHE"

	// etagFile records which database copy is current. The entry it names is a
	// directory holding that copy, so identity and content cannot disagree.
	etagFile = "etag.txt"

	// maxDBSize bounds what will be unpacked, so a corrupt or hostile archive
	// cannot exhaust the disk.
	maxDBSize = 256 << 20
)

// cacheDir returns the directory holding the cached database.
//
// Unless overridden it sits inside whichever directory the platform uses for
// caches, which os.UserCacheDir resolves: $XDG_CACHE_HOME or $HOME/.cache on
// Unix, $HOME/Library/Caches on macOS, %LocalAppData% on Windows. Since that
// varies, anything reported about the cache names the path actually in use.
func cacheDir() (string, error) {
	if dir := os.Getenv(cacheEnv); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("error locating the cache directory, set %s to choose one: %w", cacheEnv, err)
	}
	return filepath.Join(base, "go-mod-upgrade"), nil
}

// vulndbCache prepares a local copy of the vulnerability database and returns
// the directory holding it.
//
// The copy is reused between runs, and is revalidated against the server so a
// stale one is not used silently. When the server cannot be reached an existing
// copy is used and its age reported, since answering from a database of known
// age is more useful than not answering at all.
func vulndbCache(ctx context.Context) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("error creating %q: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := root.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// The recorded tag is offered to the server, which answers 304 when the
	// copy it names is still current.
	current, _ := readEtag(root)

	etag, archive, err := fetchVulndb(ctx, current)
	switch {
	case err != nil && current != "":
		log.WithFields(log.Fields{
			"error": err,
			"etag":  current,
		}).Warn("Could not reach the vulnerability database, using the cached copy")
		return filepath.Join(dir, current), nil
	case err != nil:
		return "", err
	}

	if archive == nil {
		// Unchanged, so the copy already on disk is the current one.
		log.WithField("etag", current).Debug("Vulnerability database is up to date")
		return filepath.Join(dir, current), nil
	}

	if err := unpack(root, etag, archive); err != nil {
		return "", err
	}
	if err := renameio.WriteFile(filepath.Join(dir, etagFile), []byte(etag), 0o644); err != nil {
		return "", fmt.Errorf("error recording the database version: %w", err)
	}
	// Only one copy is kept: the previous one is of no further use once the
	// recorded tag names its replacement.
	if current != "" && current != etag {
		if err := root.RemoveAll(current); err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"etag":  current,
			}).Debug("Could not remove the superseded database")
		}
	}
	log.WithField("etag", etag).Debug("Vulnerability database updated")
	return filepath.Join(dir, etag), nil
}

// readEtag returns the recorded database version, if the directory it names is
// present. A tag without its directory is meaningless, so it is reported absent.
func readEtag(root *os.Root) (string, error) {
	b, err := root.ReadFile(etagFile)
	if err != nil {
		return "", err
	}
	etag := strings.TrimSpace(string(b))
	if etag == "" {
		return "", errors.New("no database version recorded")
	}
	if _, err := root.Stat(path.Join(etag, "index", "db.json")); err != nil {
		return "", fmt.Errorf("database %q is incomplete: %w", etag, err)
	}
	return etag, nil
}

// fetchVulndb downloads the database unless the server reports that the copy
// identified by current is unchanged, in which case the archive is nil.
func fetchVulndb(ctx context.Context, current string) (etag string, archive []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulndbURL, nil)
	if err != nil {
		return "", nil, err
	}
	if current != "" {
		req.Header.Set("If-None-Match", `"`+current+`"`)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("error fetching the vulnerability database: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if resp.StatusCode == http.StatusNotModified {
		return current, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("error fetching the vulnerability database: %s", resp.Status)
	}

	etag = etagName(resp.Header.Get("ETag"))
	if etag == "" {
		return "", nil, errors.New("the vulnerability database reported no version")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDBSize))
	if err != nil {
		return "", nil, fmt.Errorf("error reading the vulnerability database: %w", err)
	}
	return etag, b, nil
}

// etagName reduces an entity tag to something usable as a single path element.
// Quotes, the weak validator prefix and any separator are removed, since the
// value is only needed to tell one copy of the database from another.
func etagName(etag string) string {
	etag = strings.TrimSpace(etag)
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.Trim(etag, `"`)
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_':
			return r
		default:
			return -1
		}
	}, etag)
}

// unpack writes the archive into a directory named for its version.
//
// Two things confine it, and both are needed. The root refuses any name
// resolving outside the cache. Cleaning each name keeps it inside the version
// directory as well: "a/../../x.json" stays within the cache but would
// otherwise land beside that directory rather than in it, where the removal
// performed on update would never reach it.
func unpack(root *os.Root, etag string, archive []byte) error {
	// A previous attempt may have left a partial copy behind.
	if err := root.RemoveAll(etag); err != nil {
		return fmt.Errorf("error clearing %q: %w", etag, err)
	}

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("error reading the vulnerability database: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := path.Join(etag, path.Clean("/"+f.Name))
		if err := root.MkdirAll(path.Dir(name), 0o755); err != nil {
			return fmt.Errorf("error creating %q: %w", path.Dir(name), err)
		}
		if err := copyZipEntry(root, name, f); err != nil {
			return err
		}
	}
	return nil
}

// copyZipEntry writes one archive entry into the cache.
func copyZipEntry(root *os.Root, name string, f *zip.File) (err error) {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("error reading %q: %w", f.Name, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	w, err := root.Create(name)
	if err != nil {
		return fmt.Errorf("error creating %q: %w", name, err)
	}
	defer func() {
		if cerr := w.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, err := io.Copy(w, io.LimitReader(rc, maxDBSize)); err != nil {
		return fmt.Errorf("error writing %q: %w", name, err)
	}
	return nil
}
