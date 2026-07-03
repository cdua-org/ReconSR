package leakix

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/schema"
)

func TestLeakixClient_RequestCreationError(t *testing.T) {
	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = "http://127.0.0.1:8080/\x7f"
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if ok {
		t.Errorf("expected request creation to fail, got ok=true")
	}
	if body != nil || status != 0 {
		t.Errorf("expected nil body and 0 status on creation error, got %v, %d", body, status)
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "create request") {
		t.Errorf("expected create request error, got %v", exec.Error)
	}
}

func TestLeakixClient_ClientDoError(t *testing.T) {
	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = "http://127.0.0.1:0"
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if ok {
		t.Errorf("expected request execution to fail, got ok=true")
	}
	if body != nil || status != 0 {
		t.Errorf("expected nil body and 0 status on client.Do error, got %v, %d", body, status)
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "do request") {
		t.Errorf("expected do request error, got %v", exec.Error)
	}
}

func TestLeakixClient_AuthError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if !ok {
		t.Errorf("expected auth error to return ok=true, got ok=false")
	}
	if body != nil || status != http.StatusForbidden {
		t.Errorf("expected nil body and 403 status, got %v, %d", body, status)
	}
}

func TestLeakixClient_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	m.lastReqTime = time.Now().Add(-2 * time.Second)

	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if ok {
		t.Errorf("expected server error to exhaust retries and fail, got ok=true")
	}
	if body != nil || status != http.StatusInternalServerError {
		t.Errorf("expected nil body and 500 status, got %v, %d", body, status)
	}
}

func TestLeakixClient_NonJSONBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Not a JSON body")); err != nil {
			panic(err)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	m.lastReqTime = time.Now().Add(-2 * time.Second)

	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if ok {
		t.Errorf("expected non-json body to exhaust retries and fail, got ok=true")
	}
	if body != nil || status != http.StatusOK {
		t.Errorf("expected nil body and 200 status, got %v, %d", body, status)
	}
}

func TestLeakixClient_RateLimitFallback(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"Services":[],"Leaks":[]}`)); err != nil {
			panic(err)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}

	body, status, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")
	if !ok {
		t.Errorf("expected request to succeed after retry, got ok=false")
	}
	if status != http.StatusOK || body == nil {
		t.Errorf("expected 200 and body, got status %d", status)
	}
}

func TestLeakixClient_RateLimitInvalidHeaderFallback(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("x-limited-for", "invalid")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"Services":[],"Leaks":[]}`)); err != nil {
			panic(err)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}

	_, _, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")
	if !ok {
		t.Errorf("expected request to succeed after retry")
	}
}

func TestLeakixClient_ReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("short")); err != nil {
			panic(err)
		}

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil && conn != nil {
				if cerr := conn.Close(); cerr != nil {
					panic(cerr)
				}
			}
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	m.lastReqTime = time.Now().Add(-2 * time.Second)

	body, _, ok := m.doAPIRequest(exec, leakixAPIBaseURL, "target")

	if ok {
		t.Errorf("expected read error to fail, got ok=true")
	}
	if body != nil {
		t.Errorf("expected nil body on read error")
	}
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errorReadCloser struct {
	io.Reader
}

func (errorReadCloser) Close() error {
	return errors.New("simulated close error")
}

func TestLeakixClient_BodyCloseError(_ *testing.T) {
	originalFunc := getHTTPClientFunc
	getHTTPClientFunc = func(_ time.Duration) *http.Client {
		return &http.Client{
			Transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       errorReadCloser{strings.NewReader(`{"data": {}}`)},
					}, nil
				},
			},
		}
	}
	defer func() { getHTTPClientFunc = originalFunc }()

	m := &leakixModule{apiKey: testKey}
	exec := &schema.ModuleExecution{}
	m.doAPIRequest(exec, "http://example.com", "target")
}

func init() {
	sleepFunc = func(time.Duration) {}
}
