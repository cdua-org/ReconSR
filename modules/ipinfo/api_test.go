package ipinfo

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIPInfo_StatusErrors(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "test-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	oldTimeout := resolver.HTTPTimeout
	oldRetries := resolver.MaxRetriesIPMeta
	oldDelay := resolver.RetryBaseDelay
	resolver.HTTPTimeout = 10 * time.Millisecond
	resolver.MaxRetriesIPMeta = 1
	resolver.RetryBaseDelay = time.Millisecond
	defer func() {
		resolver.HTTPTimeout = oldTimeout
		resolver.MaxRetriesIPMeta = oldRetries
		resolver.RetryBaseDelay = oldDelay
	}()

	m := New()

	tests := []struct {
		handler      http.HandlerFunc
		name         string
		expectedErr  string
		expectedRslt string
	}{
		{
			name: "429 Too Many Requests",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
				if _, err := w.Write([]byte("quota exceeded")); err != nil {
					t.Logf("write err: %v", err)
				}
			},
			expectedRslt: "monthly API quota exceeded (HTTP 429)",
		},
		{
			name: "500 Internal Server Error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedErr: "temporary HTTP status 500",
		},
		{
			name: "400 Bad Request",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			expectedErr: "unexpected status 400",
		},
		{
			name: "Invalid JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte("{invalid json}")); err != nil {
					t.Logf("write err: %v", err)
				}
			},
			expectedErr: "parse json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			oldAPI := defaultAPIURL
			defaultAPIURL = server.URL + "/"
			defer func() { defaultAPIURL = oldAPI }()

			out, err := m.Exec(schema.ModuleInput{
				Functions: []string{constants.FuncGetIPInfo},
				Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
			})
			if err != nil {
				t.Fatalf("unexpected exec err: %v", err)
			}

			exec := out.Executions[0]
			if tt.expectedErr != "" {
				if exec.Error == nil || !strings.Contains(*exec.Error, tt.expectedErr) {
					t.Errorf("expected error %q, got %v", tt.expectedErr, exec.Error)
				}
			} else if exec.Error != nil {
				t.Fatalf("expected no error, got: %v", *exec.Error)
			}

			if tt.expectedRslt != "" {
				if len(exec.Results) != 1 || exec.Results[0].Value != tt.expectedRslt {
					t.Errorf("expected result %q, got %v", tt.expectedRslt, exec.Results)
				}
			}
		})
	}
}

func TestIPInfo_NetworkErrors(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "test-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	oldTimeout := resolver.HTTPTimeout
	oldRetries := resolver.MaxRetriesIPMeta
	oldDelay := resolver.RetryBaseDelay
	resolver.HTTPTimeout = 10 * time.Millisecond
	resolver.MaxRetriesIPMeta = 1
	resolver.RetryBaseDelay = time.Millisecond
	defer func() {
		resolver.HTTPTimeout = oldTimeout
		resolver.MaxRetriesIPMeta = oldRetries
		resolver.RetryBaseDelay = oldDelay
	}()

	m := New()

	tests := []struct {
		name        string
		target      string
		overrideURL string
		expectedErr string
		mockPaid    bool
		timeout     bool
	}{
		{
			name:        "Invalid defaultAPIURL",
			target:      "192.0.2.2",
			overrideURL: string([]byte{0x7f}),
			expectedErr: "invalid default API URL",
		},
		{
			name:        "Invalid JoinPath",
			target:      "192.0.2.2%XX",
			overrideURL: "http://api.ipinfo.io",
			mockPaid:    true,
			expectedErr: "failed to join url path",
		},
		{
			name:        "Network Timeout",
			target:      "192.0.2.2",
			timeout:     true,
			expectedErr: "do request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockPaid {
				oldPaid := resolver.IPINFOPaid
				resolver.IPINFOPaid = true
				defer func() { resolver.IPINFOPaid = oldPaid }()
			}

			if tt.timeout {
				oldHTTPTimeout := resolver.HTTPTimeout
				resolver.HTTPTimeout = 1 * time.Millisecond
				defer func() { resolver.HTTPTimeout = oldHTTPTimeout }()

				server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
					time.Sleep(10 * time.Millisecond)
				}))
				defer server.Close()
				oldAPI := defaultAPIURL
				defaultAPIURL = server.URL + "/"
				defer func() { defaultAPIURL = oldAPI }()
			} else if tt.overrideURL != "" {
				oldAPI := defaultAPIURL
				defaultAPIURL = tt.overrideURL
				defer func() { defaultAPIURL = oldAPI }()
			}

			out, err := m.Exec(schema.ModuleInput{
				Functions: []string{constants.FuncGetIPInfo},
				Target:    schema.Entity{Type: constants.TypeIPv4, Value: tt.target},
			})
			if err != nil {
				t.Fatalf("unexpected exec err: %v", err)
			}

			exec := out.Executions[0]
			if exec.Error == nil || !strings.Contains(*exec.Error, tt.expectedErr) {
				t.Errorf("expected error %q, got %v", tt.expectedErr, exec.Error)
			}
		})
	}
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

type errorReadCloser struct {
	io.Reader
	closeErr error
}

func (e errorReadCloser) Close() error {
	if e.closeErr != nil {
		return e.closeErr
	}
	return nil
}

func TestIPInfo_TransportErrors(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "test-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	oldTimeout := resolver.HTTPTimeout
	resolver.HTTPTimeout = 10 * time.Millisecond
	defer func() { resolver.HTTPTimeout = oldTimeout }()

	m := New()

	t.Run("ReadAll Error", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		http.DefaultTransport = &mockTransport{
			roundTripFunc: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errorReadCloser{Reader: errReader{}},
				}, nil
			},
		}
		defer func() { http.DefaultTransport = oldTransport }()

		out, err := m.Exec(schema.ModuleInput{
			Functions: []string{constants.FuncGetIPInfo},
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.3"},
		})
		if err != nil {
			t.Fatalf("unexpected exec err: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil || !strings.Contains(*exec.Error, "read body: simulated read error") {
			t.Errorf("expected read error, got: %v", exec.Error)
		}
	})

	t.Run("Close Error", func(t *testing.T) {
		oldTransport := http.DefaultTransport
		http.DefaultTransport = &mockTransport{
			roundTripFunc: func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       errorReadCloser{Reader: strings.NewReader(`{"ip":"192.0.2.1"}`), closeErr: errors.New("simulated close error")},
				}, nil
			},
		}
		defer func() { http.DefaultTransport = oldTransport }()

		out, err := m.Exec(schema.ModuleInput{
			Functions: []string{constants.FuncGetIPInfo},
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.3"},
		})
		if err != nil {
			t.Fatalf("unexpected exec err: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil || !strings.Contains(*exec.Error, "read body: simulated close error") {
			t.Errorf("expected close error, got: %v", exec.Error)
		}
	})
}

func TestDoRequest_CreateError(t *testing.T) {
	_, _, headers, err := doRequest(context.Background(), ":\x00", "key")
	if err == nil || !strings.Contains(err.Error(), "create request") {
		t.Errorf("expected create request error, got: %v", err)
	}
	if headers != nil {
		t.Errorf("expected nil headers on create request error")
	}
}
