package anubis

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func overrideBaseURL(t *testing.T, url string) {
	t.Helper()
	orig := baseURL
	baseURL = url + "/"
	t.Cleanup(func() {
		baseURL = orig
	})
}

func setupMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	overrideBaseURL(t, server.URL)
	return server
}

func TestModuleCapabilities(t *testing.T) {
	mod := New()

	if mod.Name() != moduleName {
		t.Errorf("expected module name %q, got %q", moduleName, mod.Name())
	}

	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fnCaps, ok := caps.CustomFunctions[constants.FuncGetDomains]
	if !ok {
		t.Fatal("expected get_domains custom capabilities")
	}

	if len(fnCaps.InputTypes) != 1 || fnCaps.InputTypes[0] != constants.TypeDomain {
		t.Errorf("expected input type domain, got %v", fnCaps.InputTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "portal.example.com"},
		Functions: []string{"invalid_func"},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error == nil {
		t.Error("expected error for unsupported function, got nil")
	}
	if !strings.Contains(*exec.Error, "unsupported function") {
		t.Errorf("expected unsupported function error, got %q", *exec.Error)
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	resolver.HTTPTimeout = 2 * time.Second
	resolver.MaxRetriesAnubis = 1

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		data, err := os.ReadFile("testdata/response.json")
		if err != nil {
			t.Fatalf("failed to read testdata: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			panic(err)
		}
	}
	server := setupMockServer(t, handler)
	defer server.Close()

	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetDomains},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution")
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %s", *exec.Error)
	}
	if len(exec.Results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(exec.Results))
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestAnubis_Forbidden403(t *testing.T) {
	resolver.HTTPTimeout = 2 * time.Second
	resolver.MaxRetriesAnubis = 1

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`Access denied`)); err != nil {
			panic(err)
		}
	}
	server := setupMockServer(t, handler)
	defer server.Close()

	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetDomains},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec := out.Executions[0]

	if exec.Error != nil {
		t.Fatalf("expected no execution error for 403, got %q", *exec.Error)
	}
	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 result (the Info property), got %d", len(exec.Results))
	}
	res := exec.Results[0]
	if res.Type != constants.TypeInfo {
		t.Errorf("expected type %s, got %s", constants.TypeInfo, res.Type)
	}
	if !strings.Contains(res.Value, "Access denied (HTTP 403) from Anubis API") {
		t.Errorf("expected 403 message in result, got %q", res.Value)
	}
	if exec.RawData != "Access denied" {
		t.Errorf("expected raw data to contain 403 response body, got %q", exec.RawData)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestFetchAnubisData_RequestErrors(t *testing.T) {
	t.Run("create_request_error", func(t *testing.T) {
		ctx := context.Background()
		origBaseURL := baseURL
		baseURL = string([]byte{0x7f}) + "invalid"
		defer func() { baseURL = origBaseURL }()

		_, _, err := fetchAnubisData(ctx, "invalid.example.com")
		if err == nil {
			t.Error("expected error for create request")
		} else if !strings.Contains(err.Error(), "create request") {
			t.Errorf("expected create request error, got: %v", err)
		}
	})

	t.Run("client_do_error", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 2
		ctx := context.Background()
		resolver.RetryBaseDelay = 1 * time.Millisecond

		origBaseURL := baseURL
		baseURL = "http://127.0.0.1:0/anubis/"
		defer func() { baseURL = origBaseURL }()

		_, _, err := fetchAnubisData(ctx, "down.example.org")
		if err == nil {
			t.Error("expected error for client.Do failure")
		} else if !strings.Contains(err.Error(), "all API attempts failed") {
			t.Errorf("expected all API attempts failed error, got: %v", err)
		}
	})

	t.Run("client_do_error_and_context_cancelled", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 3
		ctx, cancel := context.WithCancel(context.Background())

		origBaseURL := baseURL
		baseURL = "http://127.0.0.1:0/anubis/"
		defer func() { baseURL = origBaseURL }()

		cancel()
		_, _, err := fetchAnubisData(ctx, "down.example.net")
		if err == nil {
			t.Error("expected error for client.Do failure with context cancellation")
		} else if !strings.Contains(err.Error(), "context cancelled during retry") {
			t.Errorf("expected context cancelled error, got: %v", err)
		}
	})
}

func TestFetchAnubisData_ReadBodyError(t *testing.T) {
	t.Run("read_body_error", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 1
		ctx := context.Background()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, bufrw, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cerr := conn.Close(); cerr != nil {
					t.Logf("conn.Close err: %v", cerr)
				}
			}()
			if _, werr := bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nPartial"); werr != nil {
				t.Logf("bufrw.WriteString err: %v", werr)
			}
			if ferr := bufrw.Flush(); ferr != nil {
				t.Logf("bufrw.Flush err: %v", ferr)
			}
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		_, _, err := fetchAnubisData(ctx, "partial.example.org")
		if err == nil {
			t.Error("expected error for read body")
		} else if !strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "context cancelled") && !strings.Contains(err.Error(), "all API attempts failed") {
			t.Errorf("expected read body error, got: %v", err)
		}
	})
}

func TestFetchAnubisData_ReadBodyErrorAndCancel(t *testing.T) {
	t.Run("read_body_error_and_context_cancelled", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 2
		resolver.RetryBaseDelay = 50 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("webserver doesn't support hijacking")
			}
			conn, bufrw, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			if _, werr := bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nPartial"); werr != nil {
				t.Logf("bufrw.WriteString err: %v", werr)
			}
			if ferr := bufrw.Flush(); ferr != nil {
				t.Logf("bufrw.Flush err: %v", ferr)
			}
			if cerr := conn.Close(); cerr != nil {
				t.Logf("conn.Close err: %v", cerr)
			}
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		time.AfterFunc(10*time.Millisecond, cancel)
		_, _, err := fetchAnubisData(ctx, "cancel.example.com")
		if err == nil {
			t.Error("expected error for read body with context cancellation")
		} else if !strings.Contains(err.Error(), "context cancelled during retry") {
			t.Errorf("expected context cancelled error, got: %v", err)
		}
	})
}

type mockTransport struct {
	roundTripFunc func(*http.Request) (*http.Response, error)
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

func TestFetchAnubisData_CloseBodyError(t *testing.T) {
	resolver.MaxRetriesAnubis = 1
	ctx := context.Background()

	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{strings.NewReader(`["example.com"]`)},
			}, nil
		},
	}
	defer func() { http.DefaultTransport = oldTransport }()

	origBaseURL := baseURL
	baseURL = "http://127.0.0.1/"
	defer func() { baseURL = origBaseURL }()

	_, _, err := fetchAnubisData(ctx, "close.example.org")
	if err != nil {
		t.Errorf("expected successful fetch despite close error, got: %v", err)
	}
}

func TestFetchAnubisData_Retries(t *testing.T) {
	t.Run("retryable_status_and_context_cancelled", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 3
		resolver.RetryBaseDelay = 50 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		time.AfterFunc(10*time.Millisecond, cancel)
		_, _, err := fetchAnubisData(ctx, "retry.example.net")
		if err == nil {
			t.Error("expected error for retryable status with context cancellation")
		} else if !strings.Contains(err.Error(), "context cancelled during retry") {
			t.Errorf("expected context cancelled error, got: %v", err)
		}
	})

	t.Run("hard_failure_status", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 3
		ctx := context.Background()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		_, status, err := fetchAnubisData(ctx, "fatal.example.org")
		if err == nil {
			t.Error("expected error for hard failure status")
		} else if !strings.Contains(err.Error(), "hard failure status 404") {
			t.Errorf("expected hard failure error, got: %v", err)
		}
		if status != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", status)
		}
	})

	t.Run("all_attempts_failed", func(t *testing.T) {
		resolver.MaxRetriesAnubis = 2
		ctx := context.Background()
		resolver.RetryBaseDelay = 1 * time.Millisecond

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		_, _, err := fetchAnubisData(ctx, "fail.example.com")
		if err == nil {
			t.Error("expected error for all attempts failed")
		} else if !strings.Contains(err.Error(), "all API attempts failed: retryable status 500") {
			t.Errorf("expected all attempts failed error, got: %v", err)
		}
	})
}

func TestGetDomains_Errors(t *testing.T) {
	t.Run("general_error", func(t *testing.T) {
		resolver.HTTPTimeout = 50 * time.Millisecond
		resolver.MaxRetriesAnubis = 1
		resolver.RetryBaseDelay = 1 * time.Millisecond

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		mod := New()
		input := schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeDomain, Value: "error.example.com"},
			Functions: []string{constants.FuncGetDomains},
		}

		out, err := mod.Exec(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected execution error for 500 status")
		} else if !strings.Contains(*exec.Error, "all API attempts failed") {
			t.Errorf("expected all API attempts failed error, got: %v", *exec.Error)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		resolver.HTTPTimeout = 50 * time.Millisecond
		resolver.MaxRetriesAnubis = 1

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`[`)); err != nil {
				t.Logf("write error: %v", err)
			}
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		mod := New()
		input := schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeDomain, Value: "json.example.net"},
			Functions: []string{constants.FuncGetDomains},
		}

		out, err := mod.Exec(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected execution error for invalid json")
		} else if !strings.Contains(*exec.Error, "failed to unmarshal") {
			t.Errorf("expected unmarshal error, got: %v", *exec.Error)
		}
	})
}

func TestGetDomains_Limits(t *testing.T) {
	t.Run("default_limit_and_duplicates", func(t *testing.T) {
		resolver.HTTPTimeout = 50 * time.Millisecond
		resolver.MaxRetriesAnubis = 1

		origLimit := resolver.AnubisLimit
		resolver.AnubisLimit = 0
		defer func() { resolver.AnubisLimit = origLimit }()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`["dup.example.org", "dup.example.org"]`)); err != nil {
				t.Logf("write error: %v", err)
			}
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		mod := New()
		input := schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.org"},
			Functions: []string{constants.FuncGetDomains},
		}

		out, err := mod.Exec(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exec := out.Executions[0]
		if exec.Error != nil {
			t.Fatalf("unexpected execution error: %v", *exec.Error)
		}
		if len(exec.Results) != 1 {
			t.Errorf("expected 1 result (duplicates removed), got %d", len(exec.Results))
		}
	})

	t.Run("exceeded_limit", func(t *testing.T) {
		resolver.HTTPTimeout = 50 * time.Millisecond
		resolver.MaxRetriesAnubis = 1

		origLimit := resolver.AnubisLimit
		resolver.AnubisLimit = 1
		defer func() { resolver.AnubisLimit = origLimit }()

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`["a.example.net", "b.example.net"]`)); err != nil {
				t.Logf("write error: %v", err)
			}
		}))
		defer ts.Close()

		overrideBaseURL(t, ts.URL)

		mod := New()
		input := schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.net"},
			Functions: []string{constants.FuncGetDomains},
		}

		out, err := mod.Exec(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exec := out.Executions[0]
		if exec.Error != nil {
			t.Fatalf("unexpected execution error: %v", *exec.Error)
		}
		if len(exec.Results) != 1 {
			t.Errorf("expected 1 result (limited), got %d", len(exec.Results))
		}
	})
}

func TestProcessDomain_Coverage(t *testing.T) {
	tests := []struct {
		name      string
		rawDomain string
		target    string
		valid     bool
	}{
		{
			name:      "empty_domain",
			rawDomain: "   ",
			target:    "foo.example",
			valid:     false,
		},
		{
			name:      "same_as_target",
			rawDomain: "bar.example",
			target:    "bar.example",
			valid:     false,
		},
		{
			name:      "out_of_scope",
			rawDomain: "sub.baz.example",
			target:    "qux.example",
			valid:     false,
		},
		{
			name:      "ipv4_arpa",
			rawDomain: "1.2.0.192.in-addr.arpa",
			target:    "",
			valid:     false,
		},
		{
			name:      "ipv6_arpa",
			rawDomain: "1.0.0.0.ip6.arpa",
			target:    "",
			valid:     false,
		},
		{
			name:      "invalid_validator",
			rawDomain: "invalid_domain!.example.com",
			target:    "invalid.example",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, valid := processDomain(tt.rawDomain, tt.target)
			if valid != tt.valid {
				t.Errorf("expected valid=%v, got %v", tt.valid, valid)
			}
		})
	}
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true
	}
}
