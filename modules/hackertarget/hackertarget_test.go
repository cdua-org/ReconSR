package hackertarget

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestModuleInterface(t *testing.T) {
	m := New()
	if m.Name() != moduleName {
		t.Errorf("expected name %q, got %q", moduleName, m.Name())
	}

	caps, err := m.Capabilities()
	if err != nil {
		t.Errorf("Capabilities() returned error: %v", err)
	}
	if len(caps.Functions) != 1 || caps.Functions[0] != constants.FuncGetHosts {
		t.Errorf("expected Functions ['get_hosts'], got %v", caps.Functions)
	}
	if len(caps.InputTypes) != 1 || caps.InputTypes[0] != constants.TypeDomain {
		t.Errorf("expected InputTypes ['domain'], got %v", caps.InputTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{"unsupported"},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Errorf("Exec() returned error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Function != "unsupported" {
		t.Errorf("expected Function %q, got %q", "unsupported", exec.Function)
	}
	if exec.Error == nil {
		t.Error("expected Error to be set for unsupported function")
	}
}

func TestGetHostsSuccess(t *testing.T) {
	results := parseHostSearch("sub1.tenant.example.com,192.0.2.1\nsub2.tenant.example.com,198.51.100.2\n", "tenant.example.com", modutil.NewLocalIDGenerator())

	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}
}

func TestGetHostsCSVFormat(t *testing.T) {
	results := parseHostSearch("domain1.example.com,192.0.2.1\ndomain2.example.com,198.51.100.2\n", "example.com", modutil.NewLocalIDGenerator())

	hasSubdomain := false
	hasIP := false
	for _, r := range results {
		if r.Type == constants.TypeSubdomain {
			hasSubdomain = true
		}
		if r.Type == constants.TypeIPv4 {
			hasIP = true
		}
	}
	if !hasSubdomain {
		t.Error("expected at least one subdomain result")
	}
	if !hasIP {
		t.Error("expected at least one ip result")
	}
}

func TestGetHostsInvalidCSV(t *testing.T) {
	body := "error: rate limit exceeded\n"
	if isValidCSVFormat(body) {
		t.Error("expected invalid CSV to fail validation")
	}
}

func TestIsQuotaExceeded(t *testing.T) {
	tests := []struct {
		name     string
		count    string
		quota    string
		expected bool
	}{
		{"both empty", "", "", false},
		{"count empty", "", "100", false},
		{"quota empty", "50", "", false},
		{"count less than quota", "50", "100", false},
		{"count equals quota", "100", "100", true},
		{"count exceeds quota", "150", "100", true},
		{"invalid count", "abc", "100", false},
		{"invalid quota", "50", "xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			header.Set(quotaCountHeader, tt.count)
			header.Set(quotaLimitHeader, tt.quota)

			result := isQuotaExceeded(header)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsValidCSVFormat(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"valid single line", "example.com,192.0.2.1", true},
		{"valid multiple lines", "a.example.com,192.0.2.1\nb.example.com,198.51.100.2", true},
		{"empty body", "", true},
		{"no comma", "domain.example.com", false},
		{"invalid ip", "example.com,not.an.ip", false},
		{"empty lines", "example.com,192.0.2.1\n\n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCSVFormat(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestParseHostSearch(t *testing.T) {
	results := parseHostSearch("sub1.example.com,192.0.2.1\nsub2.example.com,198.51.100.2\n", "example.com", modutil.NewLocalIDGenerator())

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	if results[0].Type != constants.TypeSubdomain || results[0].Value != "sub1.example.com" {
		t.Errorf("first result: expected {%s, %s}, got %+v", constants.TypeSubdomain, "sub1.example.com", results[0])
	}
	if results[1].Type != constants.TypeIPv4 || results[1].Value != "192.0.2.1" {
		t.Errorf("second result: expected {%s, %s}, got %+v", constants.TypeIPv4, "192.0.2.1", results[1])
	}
	if results[2].Type != constants.TypeSubdomain || results[2].Value != "sub2.example.com" {
		t.Errorf("third result: expected {%s, %s}, got %+v", constants.TypeSubdomain, "sub2.example.com", results[2])
	}
	if results[3].Type != constants.TypeIPv4 || results[3].Value != "198.51.100.2" {
		t.Errorf("fourth result: expected {%s, %s}, got %+v", constants.TypeIPv4, "198.51.100.2", results[3])
	}
}

func TestDoRequestWithAPIKey(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("tenant.example.com,192.0.2.1\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, _, _, _ = doRequest(context.Background(), "example.com", "demo-value")

	expectedURL := hostSearchPath + "example.com" + "&apikey=demo-value"
	if capturedURL != expectedURL {
		t.Errorf("expected request URL to be %q, got %q", expectedURL, capturedURL)
	}
}

func TestDoRequestWithoutAPIKey(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("tenant.example.com,192.0.2.1\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, _, _, _ = doRequest(context.Background(), "example.com", "")

	expectedURL := hostSearchPath + "example.com"
	if capturedURL != expectedURL {
		t.Errorf("expected request URL to be %q, got %q", expectedURL, capturedURL)
	}
}

func TestDoRequestQuotaExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(quotaCountHeader, "100")
		w.Header().Set(quotaLimitHeader, "100")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("tenant.example.com,192.0.2.1\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, isQuota, _, _ := doRequest(context.Background(), "example.com", "")
	if !isQuota {
		t.Error("expected doRequest to detect quota exceeded")
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	results := parseHostSearch("sub1.example.com,192.0.2.1\nsub2.example.com,198.51.100.2\n", "example.com", gen)

	if len(results) < 2 {
		t.Skip("Expected multiple results to verify chaining, skipping test")
	}

	requireUniqueLocalIDs(t, results)
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}

func TestExecGetHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("sub1.example.com,192.0.2.1\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.net"},
		Functions: []string{constants.FuncGetHosts},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Errorf("Exec() returned error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Function != constants.FuncGetHosts {
		t.Errorf("expected Function %q, got %q", constants.FuncGetHosts, exec.Function)
	}
	if exec.Error != nil {
		t.Errorf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(exec.Results))
	}
}

func TestExecGetHostsQuotaExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(quotaCountHeader, "100")
		w.Header().Set(quotaLimitHeader, "100")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("sub1.example.com,192.0.2.1\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.org"},
		Functions: []string{constants.FuncGetHosts},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Errorf("Exec() returned error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(exec.Results))
	}

	res := exec.Results[0]
	if res.Type != constants.TypeAPIQuota {
		t.Errorf("expected result type %q, got %q", constants.TypeAPIQuota, res.Type)
	}
	if res.Value != quotaExhaustedValue {
		t.Errorf("expected result value %q, got %q", quotaExhaustedValue, res.Value)
	}
}

func TestExecGetHostsError(t *testing.T) {
	oldRetry := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = oldRetry }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "test.example"},
		Functions: []string{constants.FuncGetHosts},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Errorf("Exec() returned error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results on error, got %d", len(exec.Results))
	}
	if exec.RawData != "" {
		t.Errorf("expected empty RawData on error, got %q", exec.RawData)
	}
}

func TestFetchWithRetryAbort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("invalid format string\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	body, isQuota := fetchWithRetry(context.Background(), "example.edu", "")
	if isQuota {
		t.Error("expected isQuota to be false")
	}
	if body != "" {
		t.Errorf("expected empty body, got %q", body)
	}
}

func TestFetchWithRetryContextCancel(t *testing.T) {
	oldRetry := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 10 * time.Millisecond
	defer func() { resolver.RetryBaseDelay = oldRetry }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		cancel()
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	body, isQuota := fetchWithRetry(ctx, "example.int", "")
	if isQuota {
		t.Error("expected isQuota to be false")
	}
	if body != "" {
		t.Errorf("expected empty body, got %q", body)
	}
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errReaderCloser struct {
	readErr  error
	closeErr error
}

func (e errReaderCloser) Read(_ []byte) (n int, err error) {
	if e.readErr != nil {
		return 0, e.readErr
	}
	return 0, io.EOF
}

func (e errReaderCloser) Close() error {
	return e.closeErr
}

func TestDoRequestBadURL(t *testing.T) {
	originalBaseURL := apiBaseURL
	apiBaseURL = string([]byte{0x7f})
	defer func() { apiBaseURL = originalBaseURL }()

	body, isQuota, errMsg, action := doRequest(context.Background(), "example.arpa", "")
	if body != "" || isQuota || errMsg == nil || action != httputil.Abort {
		t.Errorf("unexpected results: body=%q, isQuota=%t, errMsg=%v, action=%v", body, isQuota, errMsg, action)
	}
}

func TestDoRequestReadError(t *testing.T) {
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReaderCloser{readErr: errors.New("mock read error")},
			}, nil
		},
	}
	defer func() { http.DefaultTransport = originalTransport }()

	originalBaseURL := apiBaseURL
	apiBaseURL = "http://dummy"
	defer func() { apiBaseURL = originalBaseURL }()

	body, isQuota, errMsg, action := doRequest(context.Background(), "example.test", "")
	if body != "" || isQuota || errMsg == nil || action != httputil.Retry {
		t.Errorf("unexpected results: body=%q, isQuota=%t, errMsg=%v, action=%v", body, isQuota, errMsg, action)
	}
}

func TestDoRequestCloseError(t *testing.T) {
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReaderCloser{closeErr: errors.New("mock close error")},
			}, nil
		},
	}
	defer func() { http.DefaultTransport = originalTransport }()

	originalBaseURL := apiBaseURL
	apiBaseURL = "http://dummy"
	defer func() { apiBaseURL = originalBaseURL }()

	body, isQuota, errMsg, action := doRequest(context.Background(), "example.invalid", "")
	if body != "" || isQuota || errMsg != nil || action != 0 {
		t.Errorf("unexpected results: body=%q, isQuota=%t, errMsg=%v, action=%v", body, isQuota, errMsg, action)
	}
}

func TestParseHostSearchEdgeCases(t *testing.T) {
	body := "just.example.net\n" +
		"\n" +
		"invalid_domain!@#,192.0.2.1\n" +
		"sub.valid.example.org,not-an-ip\n" +
		"sub.good.example.net,192.0.2.2\n"

	gen := modutil.NewLocalIDGenerator()
	results := parseHostSearch(body, "example.net", gen)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if results[0].Type != constants.TypeSubdomain || results[0].Value != "sub.valid.example.org" {
		t.Errorf("first result: expected %s %s, got %+v", constants.TypeSubdomain, "sub.valid.example.org", results[0])
	}
	if results[1].Type != constants.TypeSubdomain || results[1].Value != "sub.good.example.net" {
		t.Errorf("second result: expected %s %s, got %+v", constants.TypeSubdomain, "sub.good.example.net", results[1])
	}
	if results[2].Type != constants.TypeIPv4 || results[2].Value != "192.0.2.2" {
		t.Errorf("third result: expected %s %s, got %+v", constants.TypeIPv4, "192.0.2.2", results[2])
	}
}
