package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchModuleVersions_Success(t *testing.T) {
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
		t.Errorf("unexpected item: %+v", items[0])
	}
}

func TestFetchModuleVersions_NotFound(t *testing.T) {
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
}
