package abuseipdb

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
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
		"Retry-After":           "1",
		"X-RateLimit-Remaining": "500",
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
		"Retry-After":           "29241",
		"X-RateLimit-Remaining": "0",
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
	if err := os.Setenv("RECONSR_ABUSEIPDB", "demo-api-key"); err != nil {
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
}
