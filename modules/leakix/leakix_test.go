package leakix

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const testKey = "test_key"
const testDomain = "example.com"

func loadLeakixFixture(t *testing.T, filename string) []byte {
	t.Helper()
	var data []byte
	var err error
	switch filename {
	case "service_domain_response.json":
		data, err = os.ReadFile("testdata/service_domain_response.json")
	case "service_ip_response.json":
		data, err = os.ReadFile("testdata/service_ip_response.json")
	case "subdomains_response.json":
		data, err = os.ReadFile("testdata/subdomains_response.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", filename, err)
	}
	return data
}

func newTestServer(t *testing.T, fixtureName string) func() {
	t.Helper()
	fixtureData := loadLeakixFixture(t, fixtureName)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != testKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write(fixtureData); writeErr != nil {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
		}
	}))

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	return func() {
		ts.Close()
		leakixAPIBaseURL = originalURL
	}
}

func TestLeakixDomain(t *testing.T) {
	cleanup := newTestServer(t, "service_domain_response.json")
	defer cleanup()

	m := &leakixModule{apiKey: testKey}
	target := schema.Entity{Type: constants.TypeDomain, Value: testDomain}
	exec := m.getLeakixDomain(target, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatal("Expected results, got 0")
	}

	assertHasResult(t, exec.Results, constants.TypeIPv4, "192.0.2.1")
	assertHasValueWithTag(t, exec.Results, "ptr.example.com", constants.TagReverseIP)
	assertHasResult(t, exec.Results, constants.TypePort, "443")
	assertHasResult(t, exec.Results, constants.TypePort, "22")
	assertHasResult(t, exec.Results, constants.TypeService, "https")
	assertHasResult(t, exec.Results, constants.TypeService, "ssh")
	assertHasResult(t, exec.Results, constants.TypeSource, "HttpPlugin")
	assertHasResult(t, exec.Results, constants.TypeSource, "SshPlugin")
	assertHasResult(t, exec.Results, constants.TypeDescription, "OpenSSH 8.2p1")
	assertHasResult(t, exec.Results, constants.TypeWebServer, "nginx/1.18.0")
	assertHasResult(t, exec.Results, constants.TypeJARM, "1111222233334444555566667777888811112222333344445555666677778888")
	assertHasResult(t, exec.Results, constants.TypeCertFingerprint, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	assertHasResult(t, exec.Results, constants.TypeHash, "deadbeef1234")
	assertHasResult(t, exec.Results, constants.TypeOrganization, "Fake Corp")
	assertHasResult(t, exec.Results, constants.TypeCIDR, "192.0.2.0/24")
	assertHasResult(t, exec.Results, constants.TypeTag, "web")
	assertHasValueWithTag(t, exec.Results, "Found critical config leaks", constants.TagCompromised)

	assertHasValueWithTag(t, exec.Results, "www.example.com", constants.TagSan)
	assertHasValueWithTag(t, exec.Results, "mail.example.com", constants.TagSan)

	assertHasResult(t, exec.Results, constants.TypeCertIssuer, "O: Fake CA | CN: Fake Issuer | C: FK")
	assertHasResult(t, exec.Results, constants.TypeCertNotAfter, "2027-01-01T00:00:00Z")

	assertSSHInfo(t, exec.Results)
	assertLeakedCredentials(t, exec.Results)
	assertLeakInfo(t, exec.Results)
	assertCompromisedTag(t, exec.Results)

	checkLocalIDs(t, exec.Results)
}

func TestLeakixIP(t *testing.T) {
	cleanup := newTestServer(t, "service_ip_response.json")
	defer cleanup()

	m := &leakixModule{apiKey: testKey}
	target := schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.1"}
	exec := m.getLeakixIP(target, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatal("Expected results, got 0")
	}

	assertHasResult(t, exec.Results, constants.TypeDomain, "example.net")
	assertHasResult(t, exec.Results, constants.TypeSubdomain, "sub2.example.net")
	assertHasValueWithTag(t, exec.Results, "server.example.net", constants.TagReverseIP)

	assertHasResult(t, exec.Results, constants.TypePort, "443")
	assertHasResult(t, exec.Results, constants.TypePort, "8080")
	assertHasValueWithTag(t, exec.Results, "Found critical git config leak", constants.TagCompromised)
	assertHasResult(t, exec.Results, constants.TypePort, "22")
	assertHasResult(t, exec.Results, constants.TypeService, "https")
	assertHasResult(t, exec.Results, constants.TypeService, "http")
	assertHasResult(t, exec.Results, constants.TypeService, "ssh")

	assertHasValueWithTag(t, exec.Results, "admin.example.net", constants.TagSan)

	assertLeakedCredentials(t, exec.Results)
	assertCompromisedTag(t, exec.Results)

	assertLeakSeverityOnly(t, exec.Results)
	assertEventSummary(t, exec.Results, "SshRegresshionPlugin", "Found potentially vulnerable SSH version")

	checkLocalIDs(t, exec.Results)
}

func TestLeakixRateLimit(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("x-limited-for", "1ms")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{"Services":[],"Leaks":[]}`)); writeErr != nil {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	target := schema.Entity{Type: constants.TypeDomain, Value: "example.net"}
	exec := m.getLeakixDomain(target, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error after retry, got: %v", *exec.Error)
	}
	if requestCount != 2 {
		t.Errorf("Expected 2 requests (initial + retry), got: %d", requestCount)
	}
}

func TestLeakixRateLimitExhausted(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		w.Header().Set("x-limited-for", "1ms")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	target := schema.Entity{Type: constants.TypeDomain, Value: "example.net"}
	exec := m.getLeakixDomain(target, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())

	if exec.Error == nil {
		t.Fatal("Expected error after exhausting retries")
	}
	if requestCount != resolver.MaxRetriesLeakIX {
		t.Fatalf("Expected %d retries, got %d", resolver.MaxRetriesLeakIX, requestCount)
	}
}

func assertHasResult(t *testing.T, results []schema.ModuleResult, resultType, value string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resultType && r.Value == value {
			return
		}
	}
	t.Errorf("Expected result %s=%q not found", resultType, value)
}

func assertHasValueWithTag(t *testing.T, results []schema.ModuleResult, value, tag string) {
	t.Helper()
	for _, r := range results {
		if r.Value == value && slices.Contains(r.Tags, tag) {
			return
		}
	}
	t.Errorf("Expected result with value %q and tag %q not found", value, tag)
}

func assertSSHInfo(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	for _, r := range results {
		if r.Type == constants.TypeInfo && r.Context == "SSH" && strings.Contains(r.Value, "Banner:") {
			return
		}
	}
	t.Errorf("Expected SSH info result not found")
}

func assertLeakedCredentials(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	for _, r := range results {
		if r.Type == constants.TypeLeakedData && r.Context == "Leaked Credentials" {
			return
		}
	}
	t.Errorf("Expected TypeLeakedData with Context 'Leaked Credentials' not found")
}

func assertLeakInfo(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	for _, r := range results {
		if r.Type == constants.TypeLeakedData && strings.HasPrefix(r.Value, "[high]") {
			return
		}
	}
	t.Errorf("Expected leak info with severity prefix not found")
}

func assertCompromisedTag(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	for _, r := range results {
		if slices.Contains(r.Tags, constants.TagCompromised) {
			return
		}
	}
	t.Errorf("Expected result with TagCompromised not found")
}

func checkLocalIDs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	emittedIDs := make(map[int]bool)
	for _, res := range results {
		if res.LocalID != 0 {
			if emittedIDs[res.LocalID] {
				t.Errorf("Duplicate LocalID emitted: %d for %s:%s", res.LocalID, res.Type, res.Value)
			}
			emittedIDs[res.LocalID] = true
		}
	}

	for _, res := range results {
		if res.Source != nil && res.Source.LocalID != 0 {
			if !emittedIDs[res.Source.LocalID] {
				t.Errorf("Source references unknown LocalID: %d in %s:%s", res.Source.LocalID, res.Type, res.Value)
			}
		}
	}
}

func assertLeakSeverityOnly(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	for _, r := range results {
		if r.Type == constants.TypeLeakedData && strings.HasPrefix(r.Value, "[info]") {
			return
		}
	}
	t.Errorf("Expected leak info with severity-only (empty stage) not found")
}

func assertEventSummary(t *testing.T, results []schema.ModuleResult, source, substr string) {
	t.Helper()
	for _, r := range results {
		if r.Type == constants.TypeSummary && r.Context == source && strings.Contains(r.Value, substr) {
			return
		}
	}
	t.Errorf("Expected event summary with context %q containing %q not found", source, substr)
}
