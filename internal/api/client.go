package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type VersionItem struct {
	ModulePath        string    `json:"modulePath"`
	Version           string    `json:"version"`
	CommitTime        time.Time `json:"commitTime"`
	LatestVersion     string    `json:"latestVersion"`
	Deprecated        bool      `json:"deprecated"`
	DeprecationReason string    `json:"deprecationReason"`
	Retracted         bool      `json:"retracted"`
	RetractionReason  string    `json:"retractionReason"`
}

type VersionsResponse struct {
	Items []VersionItem `json:"items"`
	Total int           `json:"total"`
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	noCache    bool
}

func NewClient(noCache bool) *Client {
	return &Client{
		BaseURL: "https://pkg.go.dev/v1beta",
		HTTPClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		noCache: noCache,
	}
}

func (c *Client) FetchModuleVersions(ctx context.Context, modulePath string) ([]VersionItem, error) {
	if !c.noCache {
		if items, ok := readCache(modulePath); ok {
			return items, nil
		}
	}

	const maxAttempts = 3
	reqURL := c.BaseURL + "/versions/" + modulePath
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return nil, err
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			lastErr = fmt.Errorf("unexpected status: %s", resp.Status)
			_ = resp.Body.Close()
			if attempt < maxAttempts-1 {
				select {
				case <-time.After(retryDelay(resp.Header, attempt)):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		case http.StatusNotFound, http.StatusGone:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("module not found: %d", resp.StatusCode)
		case http.StatusOK:
			var data VersionsResponse
			err = json.NewDecoder(resp.Body).Decode(&data)
			_ = resp.Body.Close()
			if err != nil {
				return nil, err
			}
			writeCache(modulePath, data.Items)
			return data.Items, nil
		default:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("unexpected status: %s", resp.Status)
		}
	}

	return nil, lastErr
}

// retryDelay returns how long to wait before the next attempt.
// It honours the Retry-After header when present; otherwise it uses
// exponential backoff: 4 s, 8 s, … (2<<attempt seconds).
func retryDelay(header http.Header, attempt int) time.Duration {
	if ra := header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return time.Duration(2<<attempt) * time.Second
}
