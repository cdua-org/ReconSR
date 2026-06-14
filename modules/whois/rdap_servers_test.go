package whois

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestInitRDAPServers(t *testing.T) {
	originalTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = originalTransport }()

	mockJSON := `{
		"services": [
			[
				["com", "net"],
				["https://rdap.verisign.com/com/v1/"]
			]
		]
	}`

	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(mockJSON)),
				Header:     make(http.Header),
			}, nil
		},
	}

	ianaRDAPBootstrap = sync.Once{}
	ianaRDAPServers = nil

	initRDAPServers()

	if len(ianaRDAPServers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(ianaRDAPServers))
	}
	if ianaRDAPServers["com"] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("expected url, got %s", ianaRDAPServers["com"])
	}

	initRDAPServers()
}

func TestFetchIANABootstrap_Failures(t *testing.T) {
	originalTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = originalTransport }()

	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{bad json`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	if res := fetchIANABootstrap(); res != nil {
		t.Errorf("expected nil, got %v", res)
	}

	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				Header:     make(http.Header),
			}, nil
		},
	}
	if res := fetchIANABootstrap(); res != nil {
		t.Errorf("expected nil, got %v", res)
	}

	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		},
	}
	if res := fetchIANABootstrap(); res != nil {
		t.Errorf("expected nil, got %v", res)
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestFetchIANABootstrap_ReadFailures(t *testing.T) {
	originalTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = originalTransport }()

	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(errReader{}),
				Header:     make(http.Header),
			}, nil
		},
	}
	if res := fetchIANABootstrap(); res != nil {
		t.Errorf("expected nil, got %v", res)
	}
}

func TestExtractHTTPSURL(t *testing.T) {
	res := extractHTTPSURL([]any{"http://insecure.example", "https://secure.example", 123})
	if res != "https://secure.example" {
		t.Errorf("expected https://secure.example, got %s", res)
	}

	res = extractHTTPSURL([]any{"http://insecure.example"})
	if res != "" {
		t.Errorf("expected empty string, got %s", res)
	}
}

func TestExtractTLDs(t *testing.T) {
	res := extractTLDs([]any{"info", "biz", 123})
	if len(res) != 2 || res[0] != "info" || res[1] != "biz" {
		t.Errorf("unexpected res: %v", res)
	}
}

func TestParseServiceEntry(t *testing.T) {
	entry := parseServiceEntry([][]any{
		{"tv", "io"},
		{"https://another-secure.example"},
	})
	if entry == nil || entry.URL != "https://another-secure.example" || len(entry.TLDs) != 2 {
		t.Errorf("unexpected entry: %v", entry)
	}

	entry = parseServiceEntry([][]any{{"tv"}})
	if entry != nil {
		t.Errorf("expected nil")
	}

	entry = parseServiceEntry([][]any{
		{"tv"},
		{"http://another-insecure.example"},
	})
	if entry != nil {
		t.Errorf("expected nil")
	}

	entry = parseServiceEntry([][]any{
		{123},
		{"https://yet-another.example"},
	})
	if entry != nil {
		t.Errorf("expected nil")
	}
}
