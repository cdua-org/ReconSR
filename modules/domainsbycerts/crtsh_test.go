package domainsbycerts

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"net/http"
	"testing"
	"time"
)

func TestCrtshFetch_Name(t *testing.T) {
	fetcher := newCrtshFetcher()
	if fetcher.Name() != "crt.sh" {
		t.Errorf("expected crt.sh, got %s", fetcher.Name())
	}
}

func TestCrtshFetch_NetworkError(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	originalBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalBaseURL })

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 1 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	fetcher := newCrtshFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if res != nil {
		t.Errorf("expected nil result on network error, got %v", res)
	}
}

func TestCrtshFetch_JSONError(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("{invalid json")); err != nil {
			panic(err)
		}
	})

	originalBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalBaseURL })

	fetcher := newCrtshFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if res != nil {
		t.Errorf("expected nil result on json error, got %v", res)
	}
}

func TestCrtshFetch_Success(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`[{"name_value":"node2.example.org\n\nnode3.example.org","not_after":"2024-01-01T00:00:00Z"}]`)); err != nil {
			panic(err)
		}
	})

	originalBaseURL := crtshBaseURL
	crtshBaseURL = mockServer.URL
	t.Cleanup(func() { crtshBaseURL = originalBaseURL })

	fetcher := newCrtshFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
	if res[0].value != "node2.example.org" {
		t.Errorf("expected node2.example.org, got %s", res[0].value)
	}
	if res[1].value != "node3.example.org" {
		t.Errorf("expected node3.example.org, got %s", res[1].value)
	}
}
