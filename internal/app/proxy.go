// This file is derived from github.com/fchimpan/gomod-age, used under the MIT license.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

const defaultGOPROXY = "https://proxy.golang.org,direct"

// proxyEntry represents a single entry in the GOPROXY chain.
type proxyEntry struct {
	url         string // empty for "direct"
	isDirect    bool
	fallbackAll bool // true if separated by '|' (fall through on any error)
}

// Client queries Go module proxies following the GOPROXY chain.
type Client struct {
	entries    []proxyEntry
	httpClient *http.Client
}

type Option func(*Client)

func NewClient(opts ...Option) *Client {
	c := &Client{
		entries:    parseGOPROXY(os.Getenv("GOPROXY")),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type versionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// GetVersionTime queries the GOPROXY chain for the publish time of a module version.
// Follows Go's GOPROXY protocol:
//   - comma separator: fall through to next proxy on 404/410 only
//   - pipe separator: fall through on any error
//   - "direct": skip (we cannot query VCS directly for .info)
//   - "off": stop
func (c *Client) GetVersionTime(ctx context.Context, modulePath, version string) (time.Time, error) {
	encoded := encodePath(modulePath)
	encodedVersion := encodePath(version)

	var lastErr error
	for _, entry := range c.entries {
		if entry.isDirect {
			lastErr = fmt.Errorf("module %s@%s not available via proxy (requires direct VCS access)", modulePath, version)
			continue
		}

		t, err := c.queryProxy(ctx, entry.url, encoded, encodedVersion, modulePath, version)
		if err == nil {
			return t, nil
		}

		lastErr = err

		// Determine whether to try next proxy
		if entry.fallbackAll {
			// pipe separator: fall through on any error
			continue
		}
		// comma separator: fall through only on 404/410
		if isNotFound(err) {
			continue
		}
		// Other errors (5xx, timeout, etc.): stop
		return time.Time{}, err
	}

	if lastErr != nil {
		return time.Time{}, lastErr
	}
	return time.Time{}, fmt.Errorf("no proxy configured for %s@%s", modulePath, version)
}

// proxyError wraps an HTTP error with the status code for fallback decisions.
type proxyError struct {
	statusCode int
	msg        string
}

func (e *proxyError) Error() string { return e.msg }

func isNotFound(err error) bool {
	if pe, ok := err.(*proxyError); ok {
		return pe.statusCode == http.StatusNotFound || pe.statusCode == http.StatusGone
	}
	return false
}

func (c *Client) queryProxy(ctx context.Context, baseURL, encodedPath, encodedVersion, modulePath, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", baseURL, encodedPath, encodedVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("querying proxy %s: %w", baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, &proxyError{
			statusCode: resp.StatusCode,
			msg:        fmt.Sprintf("proxy %s returned %s for %s@%s", baseURL, resp.Status, modulePath, version),
		}
	}

	var info versionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return time.Time{}, fmt.Errorf("decoding response from %s: %w", baseURL, err)
	}

	if info.Time.IsZero() {
		return time.Time{}, fmt.Errorf("proxy %s returned no publish time for %s@%s", baseURL, modulePath, version)
	}

	return info.Time, nil
}

// parseGOPROXY parses the GOPROXY environment variable into a chain of entries.
func parseGOPROXY(goproxy string) []proxyEntry {
	if goproxy == "" {
		goproxy = defaultGOPROXY
	}

	var entries []proxyEntry
	remaining := goproxy

	for remaining != "" {
		var raw string
		fallbackAll := false

		// Find the next separator
		commaIdx := strings.Index(remaining, ",")
		pipeIdx := strings.Index(remaining, "|")

		switch {
		case commaIdx < 0 && pipeIdx < 0:
			// Last entry
			raw = remaining
			remaining = ""
		case pipeIdx >= 0 && (commaIdx < 0 || pipeIdx < commaIdx):
			// Pipe separator comes first
			raw = remaining[:pipeIdx]
			remaining = remaining[pipeIdx+1:]
			fallbackAll = true
		default:
			// Comma separator comes first
			raw = remaining[:commaIdx]
			remaining = remaining[commaIdx+1:]
			fallbackAll = false
		}

		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if raw == "off" {
			break
		}

		if raw == "direct" {
			entries = append(entries, proxyEntry{isDirect: true, fallbackAll: fallbackAll})
			continue
		}

		entries = append(entries, proxyEntry{
			url:         strings.TrimRight(raw, "/"),
			fallbackAll: fallbackAll,
		})
	}

	return entries
}

// encodePath encodes a module path or version for use in proxy URLs.
// Uppercase letters are replaced with '!' followed by the lowercase letter.
func encodePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
