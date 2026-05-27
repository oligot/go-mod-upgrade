package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchModuleVersions_Success(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [
				{"modulePath": "github.com/foo/bar/v2", "version": "v2.0.0"},
				{"modulePath": "github.com/foo/bar", "version": "v1.5.0"}
			],
			"total": 2
		}`))
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}

	items, err := client.FetchModuleVersions(context.Background(), "github.com/foo/bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
	if items[0].ModulePath != "github.com/foo/bar/v2" || items[0].Version != "v2.0.0" {
		t.Errorf("unexpected item[0]: %+v", items[0])
	}
	if items[1].ModulePath != "github.com/foo/bar" || items[1].Version != "v1.5.0" {
		t.Errorf("unexpected item[1]: %+v", items[1])
	}
}

func TestFetchModuleVersions_URLNotEncoded(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"total":0}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	_, _ = client.FetchModuleVersions(context.Background(), "github.com/foo/bar")

	if gotPath != "/versions/github.com/foo/bar" {
		t.Errorf("expected unencoded path /versions/github.com/foo/bar, got %s", gotPath)
	}
}

func TestFetchModuleVersions_RetriesOn429AndSucceeds(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"modulePath":"github.com/foo/bar/v2","version":"v2.0.0"}],"total":1}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	items, err := client.FetchModuleVersions(context.Background(), "github.com/foo/bar")
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 item, got %d", len(items))
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestFetchModuleVersions_FailsAfterMaxRetries(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	_, err := client.FetchModuleVersions(context.Background(), "github.com/foo/bar")
	if err == nil {
		t.Fatal("expected error after max retries")
	}
	if attempts != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", attempts)
	}
}

func TestFetchModuleVersions_NotFound(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &Client{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}

	_, err := client.FetchModuleVersions(context.Background(), "github.com/private/repo")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "module not found: 404" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestFetchModuleVersions_UsesCache(t *testing.T) {
	t.Setenv("GOMODUPGRADE_CACHE_DIR", t.TempDir())

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"modulePath":"github.com/foo/bar/v2","version":"v2.0.0"}],"total":1}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}

	if _, err := client.FetchModuleVersions(context.Background(), "github.com/foo/bar"); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	items2, err := client.FetchModuleVersions(context.Background(), "github.com/foo/bar")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if len(items2) != 1 || items2[0].Version != "v2.0.0" {
		t.Errorf("unexpected cached data: %+v", items2)
	}

	if requests != 1 {
		t.Errorf("expected 1 HTTP request, got %d (cache not used)", requests)
	}
}
