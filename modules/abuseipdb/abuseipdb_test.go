package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func setupTestEnv(t *testing.T) {
	t.Helper()
	if err := os.Setenv("RECONSR_ABUSEIPDB", "test_key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_ABUSEIPDB"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	resolver.HTTPTimeout = 2 * time.Second
	resolver.RetryBaseDelay = time.Millisecond
}

func loadFixture(t *testing.T, fixture string) []byte {
	t.Helper()
	var data []byte
	var err error

	switch fixture {
	case "ip.json":
		data, err = os.ReadFile("testdata/ip.json")
	case "ip_whitelisted.json":
		data, err = os.ReadFile("testdata/ip_whitelisted.json")
	case "ip_tor.json":
		data, err = os.ReadFile("testdata/ip_tor.json")
	default:
		t.Fatalf("Unsupported fixture: %s", fixture)
	}

	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixture, err)
	}
	return data
}

func runModuleTest(t *testing.T, target, fixture string, statusCode int, customHeaders map[string]string) schema.ModuleExecution {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") != "test_key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		for k, v := range customHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(statusCode)
		if fixture != "" {
			data := loadFixture(t, fixture)
			if _, wErr := w.Write(data); wErr != nil {
				t.Logf("write response failed: %v", wErr)
			}
		}
	}))
	defer ts.Close()

	origAPIURL := defaultAPIURL
	defaultAPIURL = ts.URL
	defer func() { defaultAPIURL = origAPIURL }()

	m := New()
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: target},
		Functions: []string{constants.FuncCheckAbuseIPDB},
	})
	if err != nil {
		t.Fatalf("m.Exec failed: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("Expected 1 execution, got %d", len(out.Executions))
	}

	return out.Executions[0]
}

func hasResult(results []schema.ModuleResult, rType, val string) bool {
	for _, r := range results {
		if r.Type == rType && r.Value == val {
			return true
		}
	}
	return false
}

func hasResultWithTag(results []schema.ModuleResult, rType, val, tag string) bool {
	for _, r := range results {
		if r.Type == rType && r.Value == val && slices.Contains(r.Tags, tag) {
			return true
		}
	}
	return false
}

func hasReport(results []schema.ModuleResult) bool {
	for _, r := range results {
		if r.Type == constants.TypeAbuseReport && r.Value != "" {
			return true
		}
	}
	return false
}

func TestAbuseIPDB_Successful(t *testing.T) {
	setupTestEnv(t)
	exec := runModuleTest(t, "192.0.2.1", "ip.json", http.StatusOK, nil)

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatal("Expected results, got 0")
	}
	requireUniqueLocalIDs(t, exec.Results)

	if !hasResult(exec.Results, constants.TypeAbuseScore, "100") {
		t.Errorf("Missing abuse score 100")
	}
	if !hasResult(exec.Results, constants.TypeDomain, "example.com") {
		t.Errorf("Missing domain example.com")
	}
	if !hasReport(exec.Results) {
		t.Errorf("Missing abuse report")
	}
	if !hasResultWithTag(exec.Results, constants.TypeIPv4, "192.0.2.1", constants.TagMalicious) {
		t.Errorf("Missing malicious tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagBruteforce) {
		t.Errorf("Missing bruteforce tag")
	}
}

func TestAbuseIPDB_Whitelisted(t *testing.T) {
	setupTestEnv(t)
	exec := runModuleTest(t, "192.0.2.2", "ip_whitelisted.json", http.StatusOK, nil)

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}
	foundWhitelisted := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeTag && res.Value == constants.TagWhitelisted {
			foundWhitelisted = true
		}
		if res.Type == constants.TypeAbuseScore {
			t.Errorf("Did not expect abuse score (it is 0)")
		}
	}
	if !foundWhitelisted {
		t.Errorf("Expected whitelisted tag")
	}
	requireUniqueLocalIDs(t, exec.Results)
}

func TestAbuseIPDB_Tor(t *testing.T) {
	setupTestEnv(t)
	exec := runModuleTest(t, "192.0.2.3", "ip_tor.json", http.StatusOK, nil)

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagTorExit) {
		t.Errorf("Expected tor tag")
	}
	if !hasResultWithTag(exec.Results, constants.TypeIPv4, "192.0.2.3", constants.TagMalicious) {
		t.Errorf("Expected malicious tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagBruteforce) {
		t.Errorf("Expected bruteforce tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagScanner) {
		t.Errorf("Expected scanner tag")
	}
	requireUniqueLocalIDs(t, exec.Results)
}

func TestAbuseIPDB_RateLimit_Retryable(t *testing.T) {
	setupTestEnv(t)
	headers := map[string]string{
		headerRetryAfter:         "1",
		headerRateLimitRemaining: "500",
	}
	exec := runModuleTest(t, "192.0.2.4", "", http.StatusTooManyRequests, headers)

	if exec.Error == nil {
		t.Fatalf("Expected rate limit error")
	}
	if *exec.Error != "rate limited (HTTP 429)" {
		t.Errorf("Unexpected error message: %s", *exec.Error)
	}
}

func TestAbuseIPDB_RateLimit_DailyQuota(t *testing.T) {
	setupTestEnv(t)
	headers := map[string]string{
		headerRetryAfter:         "29241",
		headerRateLimitRemaining: "0",
	}
	exec := runModuleTest(t, "192.0.2.5", "", http.StatusTooManyRequests, headers)

	if exec.Error == nil {
		t.Fatalf("Expected quota exceeded error")
	}
	if *exec.Error != "daily API quota exceeded (HTTP 429), Retry-After: 29241" {
		t.Errorf("Unexpected error message: %s", *exec.Error)
	}
}

func TestAbuseIPDB_SuspiciousAndTags(t *testing.T) {
	setupTestEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"data":{"ipAddress":"192.0.2.10","abuseConfidenceScore":30,"totalReports":1,"reports":[{"categories":[10,4],"reportedAt":"2023-10-15T12:00:00+00:00","comment":"Spam and DDoS"}]}}`)); err != nil {
			t.Logf("write response failed: %v", err)
		}
	}))
	defer ts.Close()

	origAPIURL := defaultAPIURL
	defaultAPIURL = ts.URL
	defer func() { defaultAPIURL = origAPIURL }()

	m := New()
	out, err := m.Exec(schema.ModuleInput{Target: schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.10"}, Functions: []string{constants.FuncCheckAbuseIPDB}})
	if err != nil {
		t.Fatalf("m.Exec failed: %v", err)
	}
	exec := out.Executions[0]

	if !hasResultWithTag(exec.Results, constants.TypeIPv4, "192.0.2.10", constants.TagSuspicious) {
		t.Errorf("Missing suspicious tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagSpam) {
		t.Errorf("Missing spam tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagDDoS) {
		t.Errorf("Missing ddos tag")
	}
	requireUniqueLocalIDs(t, exec.Results)
}

func TestAbuseIPDB_DomainReverseIPTag(t *testing.T) {
	setupTestEnv(t)
	exec := runModuleTest(t, "192.0.2.1", "ip.json", http.StatusOK, nil)

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}

	if !hasResultWithTag(exec.Results, constants.TypeDomain, "example.com", constants.TagReverseIP) {
		t.Errorf("Domain %q missing %s tag", "example.com", constants.TagReverseIP)
	}
	if !hasResultWithTag(exec.Results, constants.TypeSubdomain, "node1.example.com", constants.TagReverseIP) {
		t.Errorf("Subdomain %q missing %s tag", "node1.example.com", constants.TagReverseIP)
	}
	if !hasResultWithTag(exec.Results, constants.TypeSubdomain, "mail.example.org", constants.TagReverseIP) {
		t.Errorf("Subdomain %q missing %s tag", "mail.example.org", constants.TagReverseIP)
	}

	for _, r := range exec.Results {
		if (r.Type == constants.TypeDomain || r.Type == constants.TypeSubdomain) && r.OutOfScope {
			t.Errorf("Domain %q must not be OutOfScope", r.Value)
		}
	}
	requireUniqueLocalIDs(t, exec.Results)
}

func TestAbuseIPDB_LocalIDChaining(t *testing.T) {
	setupTestEnv(t)
	exec := runModuleTest(t, "192.0.2.100", "ip.json", http.StatusOK, nil)

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}
	if len(exec.Results) < 2 {
		t.Fatalf("Expected multiple results to verify chaining, got %d", len(exec.Results))
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}

	requireUniqueLocalIDs(t, exec.Results)
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

func TestAbuseIPDB_DemoMode(t *testing.T) {
	if err := os.Setenv("RECONSR_ABUSEIPDB", demoIndicator); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_ABUSEIPDB"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	m := New()
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
		Functions: []string{constants.FuncCheckAbuseIPDB},
	})
	if err != nil {
		t.Fatalf("m.Exec failed: %v", err)
	}
	exec := out.Executions[0]

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %s", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatal("Expected results, got 0")
	}

	if !hasResult(exec.Results, constants.TypeInfo, "⚠️ DEMO MODE: Showing sample data for AbuseIPDB (API key not configured)") {
		t.Errorf("Missing demo mode info message")
	}
	if !hasResultWithTag(exec.Results, constants.TypeIPv4, "192.0.2.1", constants.TagMalicious) {
		t.Errorf("Missing malicious tag on target in demo mode")
	}
	if !hasResultWithTag(exec.Results, constants.TypeDomain, "example.com", constants.TagReverseIP) {
		t.Errorf("Missing domain example.com with reverse_ip tag in demo mode")
	}
	if !hasResultWithTag(exec.Results, constants.TypeSubdomain, "node1.example.com", constants.TagReverseIP) {
		t.Errorf("Missing subdomain node1.example.com with reverse_ip tag in demo mode")
	}
	requireUniqueLocalIDs(t, exec.Results)

	out2, err2 := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.2"},
		Functions: []string{constants.FuncCheckAbuseIPDB},
	})
	if err2 != nil {
		t.Fatalf("second m.Exec failed: %v", err2)
	}
	exec2 := out2.Executions[0]
	if exec2.Error != nil {
		t.Fatalf("Expected no error on second call, got: %s", *exec2.Error)
	}
	if len(exec2.Results) != 0 {
		t.Fatalf("Expected 0 results on second call, got %d", len(exec2.Results))
	}
}

func TestName(t *testing.T) {
	m := New()
	if name := m.Name(); name != "abuseipdb" {
		t.Errorf("Expected name 'abuseipdb', got '%s'", name)
	}
}

func TestCapabilities(t *testing.T) {
	t.Run("with_api_key", func(t *testing.T) {
		setupTestEnv(t)
		m := New()
		caps, err := m.Capabilities()
		if err != nil {
			t.Fatalf("Capabilities returned error: %v", err)
		}
		if caps.ModuleConfig == nil {
			t.Fatal("Expected ModuleConfig to be present")
		}
		if len(caps.Functions) == 0 {
			t.Fatal("Expected Functions to be present")
		}
	})

	t.Run("without_api_key", func(t *testing.T) {
		t.Cleanup(func() {
			if err := os.Unsetenv("RECONSR_ABUSEIPDB"); err != nil {
				t.Logf("unsetenv failed: %v", err)
			}
		})
		if err := os.Unsetenv("RECONSR_ABUSEIPDB"); err != nil {
			t.Fatalf("unsetenv failed: %v", err)
		}
		m := New()
		caps, err := m.Capabilities()
		if err != nil {
			t.Fatalf("Capabilities returned error: %v", err)
		}
		if caps.ModuleConfig != nil {
			t.Errorf("Expected nil ModuleConfig when no API key, got %+v", caps.ModuleConfig)
		}
	})
}

func TestExec_UnsupportedFunction(t *testing.T) {
	setupTestEnv(t)
	m := New()
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
		Functions: []string{"invalid_func"},
	})
	if err != nil {
		t.Fatalf("m.Exec failed: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("Expected 1 execution, got %d", len(out.Executions))
	}
	exec := out.Executions[0]
	if exec.Error == nil {
		t.Fatal("Expected error for unsupported function, got nil")
	}
	expectedErr := "unsupported function: invalid_func"
	if *exec.Error != expectedErr {
		t.Errorf("Expected error '%s', got '%s'", expectedErr, *exec.Error)
	}
}

func TestAbuseIPDB_ProcessCheckCoverage(t *testing.T) {
	setupTestEnv(t)

	t.Run("maxAge_less_than_1", func(t *testing.T) {
		origMax := resolver.AbuseIPDBmaxAgeInDays
		resolver.AbuseIPDBmaxAgeInDays = 0
		defer func() { resolver.AbuseIPDBmaxAgeInDays = origMax }()
		exec := runModuleTest(t, "192.0.2.1", "ip.json", http.StatusOK, nil)
		if exec.Error != nil {
			t.Errorf("expected no error, got %v", *exec.Error)
		}
	})

	t.Run("maxAge_greater_than_365", func(t *testing.T) {
		origMax := resolver.AbuseIPDBmaxAgeInDays
		resolver.AbuseIPDBmaxAgeInDays = 400
		defer func() { resolver.AbuseIPDBmaxAgeInDays = origMax }()
		exec := runModuleTest(t, "192.0.2.2", "ip.json", http.StatusOK, nil)
		if exec.Error != nil {
			t.Errorf("expected no error, got %v", *exec.Error)
		}
	})

	t.Run("invalid_url", func(t *testing.T) {
		origURL := defaultAPIURL
		defaultAPIURL = "://invalid-url"
		defer func() { defaultAPIURL = origURL }()

		m := New()
		out, err := m.Exec(schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.3"},
			Functions: []string{constants.FuncCheckAbuseIPDB},
		})
		if err != nil {
			t.Fatalf("m.Exec failed: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected error for invalid URL")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			time.Sleep(10 * time.Millisecond)
		}))
		defer ts.Close()

		origURL := defaultAPIURL
		defaultAPIURL = ts.URL
		defer func() { defaultAPIURL = origURL }()

		origTimeout := resolver.HTTPTimeout
		resolver.HTTPTimeout = 2 * time.Millisecond
		defer func() { resolver.HTTPTimeout = origTimeout }()

		m := New()
		out, err := m.Exec(schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.4"},
			Functions: []string{constants.FuncCheckAbuseIPDB},
		})
		if err != nil {
			t.Fatalf("m.Exec failed: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected error for timeout")
		}
	})

	t.Run("network_error_retries", func(t *testing.T) {
		origURL := defaultAPIURL
		defaultAPIURL = "http://127.0.0.1:0"
		defer func() { defaultAPIURL = origURL }()

		m := New()
		out, err := m.Exec(schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.5"},
			Functions: []string{constants.FuncCheckAbuseIPDB},
		})
		if err != nil {
			t.Fatalf("m.Exec failed: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected error for network failure")
		}
	})

	t.Run("unexpected_status_500", func(t *testing.T) {
		exec := runModuleTest(t, "192.0.2.6", "", http.StatusInternalServerError, nil)
		if exec.Error == nil {
			t.Error("expected error for status 500")
		} else if !strings.Contains(*exec.Error, "unexpected status 500") {
			t.Errorf("expected unexpected status 500, got %v", *exec.Error)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, wErr := w.Write([]byte("{invalid-json")); wErr != nil {
				t.Logf("write error: %v", wErr)
			}
		}))
		defer ts.Close()

		origURL := defaultAPIURL
		defaultAPIURL = ts.URL
		defer func() { defaultAPIURL = origURL }()

		m := New()
		out, err := m.Exec(schema.ModuleInput{
			Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.7"},
			Functions: []string{constants.FuncCheckAbuseIPDB},
		})
		if err != nil {
			t.Fatalf("m.Exec failed: %v", err)
		}
		exec := out.Executions[0]
		if exec.Error == nil {
			t.Error("expected error for invalid json")
		} else if !strings.Contains(*exec.Error, "parse json") {
			t.Errorf("expected parse json error, got %v", *exec.Error)
		}
	})
}

func TestDoRequest_Coverage(t *testing.T) {
	setupTestEnv(t)

	t.Run("create_request_error", func(t *testing.T) {
		ctx := context.Background()
		invalidURL := string([]byte{0x7f})
		_, _, _, err := doRequest(ctx, invalidURL, "test_key")
		if err == nil {
			t.Error("expected error for invalid URL in doRequest")
		} else if !strings.Contains(err.Error(), "create request") {
			t.Errorf("expected create request error, got: %v", err)
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		ctx := context.Background()
		_, _, _, err := doRequest(ctx, ts.URL, "test_key")
		if err == nil {
			t.Error("expected error for read body")
		} else if !strings.Contains(err.Error(), "read body") {
			t.Errorf("expected read body error, got: %v", err)
		}
	})
}

func TestIsDailyQuotaExceeded_Coverage(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		name     string
		expected bool
	}{
		{
			name:     "remaining_zero",
			headers:  map[string]string{headerRateLimitRemaining: "0"},
			expected: true,
		},
		{
			name:     "retry_after_gt_60",
			headers:  map[string]string{headerRetryAfter: "61"},
			expected: true,
		},
		{
			name:     "retry_after_eq_60",
			headers:  map[string]string{headerRetryAfter: "60"},
			expected: false,
		},
		{
			name:     "invalid_retry_after",
			headers:  map[string]string{headerRetryAfter: "abc"},
			expected: false,
		},
		{
			name:     "empty_headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			if got := isDailyQuotaExceeded(h); got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestPopulateMoreResults_Coverage(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	resp := &abuseIPDBResponse{}
	resp.Data.Hostnames = []string{
		"",
		"valid.example.com",
		"invalid host name",
	}

	populateMoreResults(exec, resp, gen)

	foundInvalidHost := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeHostname && res.Value == "invalid host name" {
			foundInvalidHost = true
			break
		}
	}

	if !foundInvalidHost {
		t.Errorf("expected to find invalid hostname added as constants.TypeHostname")
	}
}

func TestParseReports_Coverage(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	resp := &abuseIPDBResponse{}
	resp.Data.TotalReports = 1
	resp.Data.Reports = []struct {
		ReportedAt string `json:"reportedAt"`
		Comment    string `json:"comment"`
		Categories []int  `json:"categories"`
	}{
		{
			ReportedAt: "2024-01-01T00:00:00Z",
			Comment:    "Test report",
			Categories: []int{999},
		},
	}

	parseReports(exec, resp, gen)

	foundUnknownCategory := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeAbuseReport && strings.Contains(res.Value, "Unknown Category 999") {
			foundUnknownCategory = true
			break
		}
	}

	if !foundUnknownCategory {
		t.Errorf("expected to find abuse report result with 'Unknown Category 999'")
	}
}

func TestAbuseIPDB_DemoMode_Error(t *testing.T) {
	if err := os.Setenv("RECONSR_ABUSEIPDB", demoIndicator); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_ABUSEIPDB"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	oldDemoData := demoData
	demoData = []byte(`{invalid json`)
	defer func() { demoData = oldDemoData }()

	m := New()
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.10"},
		Functions: []string{constants.FuncCheckAbuseIPDB},
	})
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	exec := out.Executions[0]
	if exec.Error == nil {
		t.Fatal("expected error for invalid demo JSON")
	}
	if !strings.Contains(*exec.Error, "unmarshal fixture err") {
		t.Errorf("expected unmarshal error, got: %v", *exec.Error)
	}
}
