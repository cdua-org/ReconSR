package domainsbycerts

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errorReadCloser struct {
	io.Reader
	closeErr error
	readErr  error
}

func (e errorReadCloser) Read(p []byte) (n int, err error) {
	if e.readErr != nil {
		return 0, e.readErr
	}
	return e.Reader.Read(p)
}

func (e errorReadCloser) Close() error {
	return e.closeErr
}

func TestDoRequestWithRetry_BadURL(t *testing.T) {
	_, err := doRequestWithRetry(context.Background(), "http://example.com/\x7f")
	if err == nil || !strings.Contains(err.Error(), "create request") {
		t.Errorf("expected create request error, got %v", err)
	}
}

func TestDoRequestWithRetry_DoErrorAndContextCancel(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("simulated network error")
		},
	}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := doRequestWithRetry(ctx, "http://example.com")
	if err == nil || !strings.Contains(err.Error(), "context cancelled during retry") {
		t.Errorf("expected context cancelled error, got %v", err)
	}
}

func TestDoRequestWithRetry_ReadBodyError(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: errorReadCloser{
					Reader:  strings.NewReader(""),
					readErr: errors.New("simulated read error"),
				},
			}, nil
		},
	}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := doRequestWithRetry(ctx, "http://example.com")
	if err == nil || !strings.Contains(err.Error(), "context cancelled during retry") {
		t.Errorf("expected context cancelled error, got %v", err)
	}
}

func TestDoRequestWithRetry_CloseBodyError(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: errorReadCloser{
					Reader:   strings.NewReader(`{"ok":true}`),
					closeErr: errors.New("simulated close error"),
				},
			}, nil
		},
	}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	res, err := doRequestWithRetry(context.Background(), "http://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res) != `{"ok":true}` {
		t.Errorf("expected ok:true, got %s", string(res))
	}
}

func TestDoRequestWithRetry_LargeBody(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		largeBody := strings.Repeat("A", 600)
		if _, err := w.Write([]byte(largeBody)); err != nil {
			panic(err)
		}
	})

	res, err := doRequestWithRetry(context.Background(), mockServer.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 600 {
		t.Errorf("expected 600 bytes, got %d", len(res))
	}
}

func TestDoRequestWithRetry_AbortStatus(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`Not Found`)); err != nil {
			panic(err)
		}
	})

	_, err := doRequestWithRetry(context.Background(), mockServer.URL)
	if err == nil || !strings.Contains(err.Error(), "hard failure status 404") {
		t.Errorf("expected 404 abort error, got %v", err)
	}
}

func TestDoRequestWithRetry_RetryableStatusAndContextCancel(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 50 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	_, err := doRequestWithRetry(ctx, mockServer.URL)
	if err == nil || !strings.Contains(err.Error(), "context cancelled during retry") {
		t.Errorf("expected context cancelled error, got %v", err)
	}
}

func TestDoRequestWithRetry_MaxRetriesExhausted(t *testing.T) {
	mockServer := newMockServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	resolver.MaxRetriesCert = 2
	defer func() { resolver.MaxRetriesCert = 3 }()

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 1 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	_, err := doRequestWithRetry(context.Background(), mockServer.URL)
	if err == nil || !strings.Contains(err.Error(), "retryable status 500") {
		t.Errorf("expected 500 retryable error after exhaust, got %v", err)
	}
}

func TestDoRequestWithRetry_DoError_Retries(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("simulated network error")
		},
	}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	resolver.MaxRetriesCert = 2
	defer func() { resolver.MaxRetriesCert = 3 }()

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 1 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	_, err := doRequestWithRetry(context.Background(), "http://example.com")
	if err == nil || !strings.Contains(err.Error(), "simulated network error") {
		t.Errorf("expected do request error after exhaust, got %v", err)
	}
}

func TestDoRequestWithRetry_ReadBodyError_Retries(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: errorReadCloser{
					Reader:  strings.NewReader(""),
					readErr: errors.New("simulated read error"),
				},
			}, nil
		},
	}
	t.Cleanup(func() { http.DefaultTransport = oldTransport })

	resolver.MaxRetriesCert = 2
	defer func() { resolver.MaxRetriesCert = 3 }()

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 1 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	_, err := doRequestWithRetry(context.Background(), "http://example.com")
	if err == nil || !strings.Contains(err.Error(), "read body: simulated read error") {
		t.Errorf("expected read body error after exhaust, got %v", err)
	}
}
