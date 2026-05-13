package abuseipdb

import (
	"net/http"
	"net/http/httptest"
	"os"
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
		Target:    schema.Entity{Value: target},
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

	if !hasResult(exec.Results, constants.TypeAbuseScore, "100") {
		t.Errorf("Missing abuse score 100")
	}
	if !hasResult(exec.Results, constants.TypeDomain, "example.com") {
		t.Errorf("Missing domain example.com")
	}
	if !hasReport(exec.Results) {
		t.Errorf("Missing abuse report")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagMalicious) {
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
	if !hasResult(exec.Results, constants.TypeTag, constants.TagMalicious) {
		t.Errorf("Expected malicious tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagBruteforce) {
		t.Errorf("Expected bruteforce tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagScanner) {
		t.Errorf("Expected scanner tag")
	}
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
	out, err := m.Exec(schema.ModuleInput{Target: schema.Entity{Value: "192.0.2.10"}, Functions: []string{constants.FuncCheckAbuseIPDB}})
	if err != nil {
		t.Fatalf("m.Exec failed: %v", err)
	}
	exec := out.Executions[0]

	if !hasResult(exec.Results, constants.TypeTag, constants.TagSuspicious) {
		t.Errorf("Missing suspicious tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagSpam) {
		t.Errorf("Missing spam tag")
	}
	if !hasResult(exec.Results, constants.TypeTag, constants.TagDDoS) {
		t.Errorf("Missing ddos tag")
	}
}
