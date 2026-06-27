package domainsbycerts

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newMockServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(func() {
		server.Close()
	})
	return server
}

func TestCertspotterFetch_NetworkError(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	originalBaseURL := certspotterBaseURL
	certspotterBaseURL = mockServer.URL
	t.Cleanup(func() { certspotterBaseURL = originalBaseURL })

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 1 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	fetcher := newCertspotterFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if res != nil {
		t.Errorf("expected nil result on network error, got %v", res)
	}
}

func TestCertspotterFetch_JSONError(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("{invalid json")); err != nil {
			panic(err)
		}
	})

	originalBaseURL := certspotterBaseURL
	certspotterBaseURL = mockServer.URL
	t.Cleanup(func() { certspotterBaseURL = originalBaseURL })

	fetcher := newCertspotterFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if res != nil {
		t.Errorf("expected nil result on json error, got %v", res)
	}
}

func TestCertspotterFetch_Success(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`[{"not_before":"2023-01-01T00:00:00Z","not_after":"2024-01-01T00:00:00Z","dns_names":["node1.example.org"]}]`)); err != nil {
			panic(err)
		}
	})

	originalBaseURL := certspotterBaseURL
	certspotterBaseURL = mockServer.URL
	t.Cleanup(func() { certspotterBaseURL = originalBaseURL })

	fetcher := newCertspotterFetcher()
	res := fetcher.Fetch(context.Background(), "example.com")
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].value != "node1.example.org" {
		t.Errorf("expected node1.example.org, got %s", res[0].value)
	}
}
