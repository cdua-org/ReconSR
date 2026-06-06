package netlas

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func init() {
	resolver.NetlasRetryBaseDelay = 5 * time.Millisecond
	netlasRateLimitDelay = 0
}

type clientErrorTestCase struct {
	name           string
	body           string
	expectErrMatch string
	expectedResult string
	statusCode     int
	expectError    bool
	expectResult   bool
}

func TestClientErrors(t *testing.T) {
	tests := []clientErrorTestCase{
		{
			name:           "401_Unauthorized",
			statusCode:     http.StatusUnauthorized,
			body:           `{"error": "Unauthorized"}`,
			expectResult:   true,
			expectedResult: "Netlas API Key is invalid or forbidden (HTTP 401)",
		},
		{
			name:           "402_Payment_Required",
			statusCode:     http.StatusPaymentRequired,
			body:           `{"error": "Payment Required"}`,
			expectResult:   true,
			expectedResult: "Netlas Quota Exhausted (HTTP 402)",
		},
		{
			name:           "400_Bad_Request",
			statusCode:     http.StatusBadRequest,
			body:           `{"title": "Bad Request", "detail": "Invalid Input"}`,
			expectResult:   true,
			expectedResult: "Netlas API Error: Bad Request - Invalid Input",
		},
		{
			name:           "400_Bad_Request_Title_Only",
			statusCode:     http.StatusBadRequest,
			body:           `{"title": "Bad Request Only"}`,
			expectResult:   true,
			expectedResult: "Netlas API Error: Bad Request Only",
		},
		{
			name:         "404_Not_Found",
			statusCode:   http.StatusNotFound,
			body:         `{"error": "Not Found"}`,
			expectResult: false,
		},
		{
			name:           "429_Rate_Limit",
			statusCode:     http.StatusTooManyRequests,
			body:           `{"error": "Too Many Requests"}`,
			expectResult:   true,
			expectedResult: "Netlas Rate Limit Exceeded (HTTP 429)",
		},
		{
			name:           "429_Rate_Limit_No_Header",
			statusCode:     http.StatusTooManyRequests,
			body:           `{"error": "Too Many Requests"}`,
			expectResult:   true,
			expectedResult: "Netlas Rate Limit Exceeded (HTTP 429)",
		},
		{
			name:           "429_Daily_Limit",
			statusCode:     http.StatusTooManyRequests,
			body:           `{"type": "daily_request_limit_exceeded", "title": "Daily request limit exceeded"}`,
			expectResult:   true,
			expectedResult: "Netlas API Error: Daily request limit exceeded",
		},
		{
			name:           "500_Server_Error",
			statusCode:     http.StatusInternalServerError,
			body:           `{"type": "server_error", "title": "Internal Server Error", "detail": "Details..."}`,
			expectError:    true,
			expectErrMatch: "status: 500",
			expectResult:   true,
			expectedResult: "Netlas API Error: Internal Server Error - Details...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runClientErrorTest(t, tt)
		})
	}

	t.Run("CreateRequestError", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("expected *netlasModule")
		}
		m.apiKey = "fake-key-create"
		exec := &schema.ModuleExecution{Function: "CreateReqTest"}
		gen := modutil.NewLocalIDGenerator()

		raw, ok := m.doAPIRequest(exec, "://invalid-url", "example.net", gen)
		if ok || raw != nil {
			t.Errorf("expected false and nil for invalid url")
		}
		if exec.Error == nil || !strings.Contains(*exec.Error, "create request") {
			t.Errorf("expected create request error, got %v", exec.Error)
		}
	})

	t.Run("DoRequestError", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("expected *netlasModule")
		}
		m.apiKey = "fake-key-do"
		exec := &schema.ModuleExecution{Function: "DoReqTest"}
		gen := modutil.NewLocalIDGenerator()

		raw, ok := m.doAPIRequest(exec, "http://127.0.0.1:0", "example.org", gen)
		if ok || raw != nil {
			t.Errorf("expected false and nil for unreachable host")
		}
		if exec.Error == nil || !strings.Contains(*exec.Error, "do request") {
			t.Errorf("expected do request error, got %v", exec.Error)
		}
	})
}

func assertClientErrorState(t *testing.T, exec *schema.ModuleExecution, expectError bool, expectErrMatch string) {
	t.Helper()
	if expectError {
		if exec.Error == nil {
			t.Errorf("expected exec.Error to be set")
		} else if expectErrMatch != "" && !strings.Contains(*exec.Error, expectErrMatch) {
			t.Errorf("expected error to contain %q, got %q", expectErrMatch, *exec.Error)
		}
	} else if exec.Error != nil {
		t.Errorf("expected no exec.Error, got %v", *exec.Error)
	}
}

func assertClientResultState(t *testing.T, exec *schema.ModuleExecution, expectResult bool, expectedResult string) {
	t.Helper()
	if expectResult {
		found := false
		for _, res := range exec.Results {
			if res.Type == constants.TypeInfo && res.Value == expectedResult {
				found = true
			}
		}
		if !found {
			t.Errorf("expected Info Error %q, not found", expectedResult)
		}
	} else if len(exec.Results) > 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func runClientErrorTest(t *testing.T, tt clientErrorTestCase) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if tt.statusCode == http.StatusTooManyRequests && tt.name != "429_Rate_Limit_No_Header" {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(tt.statusCode)
		if _, err := w.Write([]byte(tt.body)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	m, ok := New().(*netlasModule)
	if !ok {
		t.Fatal("expected *netlasModule")
	}
	m.apiKey = "fake-key-errors"
	m.lastReqTime = time.Time{}

	exec := &schema.ModuleExecution{Function: "ErrorHandling"}
	gen := modutil.NewLocalIDGenerator()

	raw, _ := m.doAPIRequest(exec, server.URL+"/test", "client.example.com", gen)

	if raw != nil {
		t.Fatalf("expected raw body to be nil")
	}

	assertClientErrorState(t, exec, tt.expectError, tt.expectErrMatch)
	assertClientResultState(t, exec, tt.expectResult, tt.expectedResult)
}

func TestClientState(t *testing.T) {
	m, ok := New().(*netlasModule)
	if !ok {
		t.Fatal("expected *netlasModule")
	}
	m.apiKey = "fake-key-state"
	m.lastReqTime = time.Time{}
	exec := &schema.ModuleExecution{Function: "StateTest"}
	gen := modutil.NewLocalIDGenerator()

	m.keyInvalid.Store(true)
	_, ok = m.doAPIRequest(exec, "http://localhost", "state.example.net", gen)
	if ok {
		t.Errorf("expected failure when keyInvalid is true")
	}

	m.keyInvalid.Store(false)
	m.quotaBlocked.Store(true)
	_, ok = m.doAPIRequest(exec, "http://localhost", "quota.example.org", gen)
	if ok {
		t.Errorf("expected failure when quotaBlocked is true")
	}
}

func TestPreflight(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		expectMsg     string
		statusCode    int
		expectInvalid bool
		expectQuota   bool
	}{
		{
			name:          "200_OK_Valid",
			body:          `{"plan": {"coins": 100, "limit_per_one_download": 50}}`,
			statusCode:    http.StatusOK,
			expectInvalid: false,
			expectQuota:   false,
		},
		{
			name:          "200_OK_InvalidJSON",
			body:          `{invalid`,
			statusCode:    http.StatusOK,
			expectInvalid: true,
			expectQuota:   false,
			expectMsg:     "Netlas API Error: Failed to parse user profile",
		},
		{
			name:          "401_Unauthorized",
			body:          `{"error": "Unauthorized"}`,
			statusCode:    http.StatusUnauthorized,
			expectInvalid: true,
			expectQuota:   false,
			expectMsg:     "Netlas API Error (HTTP 401)",
		},
		{
			name:          "402_Payment_Required",
			body:          `{"error": "Payment Required"}`,
			statusCode:    http.StatusPaymentRequired,
			expectInvalid: false,
			expectQuota:   true,
			expectMsg:     "Netlas Quota Exhausted (HTTP 402)",
		},
		{
			name:          "404_Not_Found",
			body:          `{"error": "Not Found"}`,
			statusCode:    http.StatusNotFound,
			expectInvalid: true,
			expectQuota:   false,
			expectMsg:     "Netlas API Error (HTTP 404)",
		},
		{
			name:          "429_Too_Many_Requests",
			body:          `{"error": "Rate Limit"}`,
			statusCode:    http.StatusTooManyRequests,
			expectInvalid: true,
			expectQuota:   false,
			expectMsg:     "Netlas API Error: Max retries exhausted (HTTP 429)",
		},
		{
			name:          "500_Server_Error",
			body:          `{"error": "Internal Server Error"}`,
			statusCode:    http.StatusInternalServerError,
			expectInvalid: true,
			expectQuota:   false,
			expectMsg:     "Netlas API Error: Max retries exhausted (HTTP 500)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Errorf("write error: %v", err)
				}
			}))
			defer server.Close()

			originalURL := netlasAPIBaseURL
			netlasAPIBaseURL = server.URL
			defer func() { netlasAPIBaseURL = originalURL }()

			m, ok := New().(*netlasModule)
			if !ok {
				t.Fatal("expected *netlasModule")
			}
			m.apiKey = "fake-key-preflight"
			m.handlePreflightAPI()

			if m.keyInvalid.Load() != tt.expectInvalid {
				t.Errorf("expected keyInvalid=%v, got %v", tt.expectInvalid, m.keyInvalid.Load())
			}
			if m.quotaBlocked.Load() != tt.expectQuota {
				t.Errorf("expected quotaBlocked=%v, got %v", tt.expectQuota, m.quotaBlocked.Load())
			}
			if tt.expectMsg != "" && !strings.Contains(m.invalidMsg, tt.expectMsg) {
				t.Errorf("expected msg containing %q, got %q", tt.expectMsg, m.invalidMsg)
			}
		})
	}
}

func TestPreflightErrors(t *testing.T) {
	t.Run("CreateRequestError", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("failed to cast module")
		}
		m.apiKey = "fake-key-1"
		originalURL := netlasAPIBaseURL
		netlasAPIBaseURL = "://invalid-url"
		defer func() { netlasAPIBaseURL = originalURL }()

		_, _, success := m.executePreflightRequest()
		if success {
			t.Errorf("expected false for invalid url")
		}
	})

	t.Run("DoRequestError", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("failed to cast module")
		}
		m.apiKey = "fake-key-2"
		originalURL := netlasAPIBaseURL
		netlasAPIBaseURL = "http://127.0.0.1:0"
		defer func() { netlasAPIBaseURL = originalURL }()

		_, _, success := m.executePreflightRequest()
		if success {
			t.Errorf("expected false for unreachable host")
		}
	})

	t.Run("HandlePreflightKeyInvalidAlready", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("failed to cast module")
		}
		m.apiKey = "fake-key-3"
		m.keyInvalid.Store(true)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		originalURL := netlasAPIBaseURL
		netlasAPIBaseURL = server.URL
		defer func() { netlasAPIBaseURL = originalURL }()

		m.handlePreflightAPI()
		if m.invalidMsg != "" {
			t.Errorf("expected invalidMsg to remain empty, got %q", m.invalidMsg)
		}
	})

	t.Run("ReadBodyError", func(t *testing.T) {
		m, ok := New().(*netlasModule)
		if !ok {
			t.Fatal("failed to cast module")
		}
		m.apiKey = "fake-key-4"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			// Truncate body to cause io.ReadAll to fail
		}))
		defer server.Close()
		originalURL := netlasAPIBaseURL
		netlasAPIBaseURL = server.URL
		defer func() { netlasAPIBaseURL = originalURL }()

		_, _, success := m.executePreflightRequest()
		if success {
			t.Errorf("expected false for read body error")
		}
	})
}

func TestRateLimitDelays(t *testing.T) {
	originalDelay := netlasRateLimitDelay
	netlasRateLimitDelay = 1 * time.Millisecond
	defer func() { netlasRateLimitDelay = originalDelay }()

	m, ok := New().(*netlasModule)
	if !ok {
		t.Fatal("failed to cast module")
	}

	m.lastReqTime = time.Now()
	m.waitRateLimit()

	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sleepOnRateLimitNetlas(ctx, resp, 1)
}
