package leakix

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

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

func TestLeakixDomain_BlockedAPIKey(t *testing.T) {
	m := &leakixModule{apiKey: testKey}
	m.blockedStatus.Store(401)
	out := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if len(out.Results) == 0 || !strings.Contains(out.Results[0].Value, "API key invalid") {
		t.Errorf("Expected blocked message, got %v", out.Results)
	}

	m.blockedStatus.Store(403)
	out2 := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if len(out2.Results) == 0 || !strings.Contains(out2.Results[0].Value, "API access blocked (HTTP 403)") {
		t.Errorf("Expected HTTP 403 blocked message, got %v", out2.Results)
	}
}

func TestLeakixDomain_NetworkError(t *testing.T) {
	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = "http://127.0.0.2:0"
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if out.Error == nil {
		t.Error("Expected network error")
	}
}

func TestLeakixDomain_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if out.Error != nil {
		t.Errorf("Expected no error for 404, got %v", out.Error)
	}
	if len(out.Results) != 0 {
		t.Errorf("Expected 0 results for 404, got %d", len(out.Results))
	}
}

func TestLeakixDomain_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if out.Error == nil || !strings.Contains(*out.Error, "http status: 400") {
		t.Errorf("Expected http status: 400 error, got %v", out.Error)
	}
}

func TestLeakixDomain_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{"broken":`)); writeErr != nil {
			panic(writeErr)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixDomain(schema.Entity{Type: constants.TypeDomain, Value: testDomain}, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())
	if out.Error == nil || !strings.Contains(*out.Error, "parse json") {
		t.Error("Expected JSON parse error")
	}
}

func TestLeakixIP_BlockedAPIKey(t *testing.T) {
	m := &leakixModule{apiKey: testKey}
	m.blockedStatus.Store(401)
	out := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.2"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if len(out.Results) == 0 || !strings.Contains(out.Results[0].Value, "API key invalid") {
		t.Errorf("Expected blocked message, got %v", out.Results)
	}

	m.blockedStatus.Store(403)
	out2 := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.3"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if len(out2.Results) == 0 || !strings.Contains(out2.Results[0].Value, "API access blocked (HTTP 403)") {
		t.Errorf("Expected HTTP 403 blocked message, got %v", out2.Results)
	}
}

func TestLeakixIP_NetworkError(t *testing.T) {
	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = "http://127.0.0.2:0"
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.4"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if out.Error == nil {
		t.Error("Expected network error")
	}
}

func TestLeakixIP_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.5"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if out.Error != nil {
		t.Errorf("Expected no error for 404, got %v", out.Error)
	}
	if len(out.Results) != 0 {
		t.Errorf("Expected 0 results for 404, got %d", len(out.Results))
	}
}

func TestLeakixIP_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.6"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if out.Error == nil || !strings.Contains(*out.Error, "http status: 400") {
		t.Errorf("Expected http status: 400 error, got %v", out.Error)
	}
}

func TestLeakixIP_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{"broken":`)); writeErr != nil {
			panic(writeErr)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out := m.getLeakixIP(schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.7"}, constants.FuncGetLeakIXIP, modutil.NewLocalIDGenerator())
	if out.Error == nil || !strings.Contains(*out.Error, "parse json") {
		t.Error("Expected JSON parse error")
	}
}
func TestLeakixDomain_ParsingEdgeCases(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte(`{
			"Services": [
				{
					"ip": "198.51.100.20",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"service": {
						"credentials": {
							"username": "admin",
							"password": "123"
						}
					}
				},
				{
					"ip": "198.51.100.20",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-02T10:00:00Z",
					"service": {
						"credentials": {
							"username": "admin",
							"password": "123"
						}
					}
				},
				{
					"ip": "198.51.100.22",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"leak": {
						"stage": "initial",
						"type": "auth",
						"severity": "high"
					}
				},
				{
					"ip": "198.51.100.22",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-02T10:00:00Z",
					"leak": {
						"stage": "initial",
						"type": "auth",
						"severity": "high"
					}
				},
				{
					"ip": "198.51.100.23",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"event_type": "leak",
					"summary": "This is a summary text"
				},
				{
					"ip": "198.51.100.23",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-02T10:00:00Z",
					"event_type": "leak",
					"summary": "This is a summary text"
				},
				{
					"ip": "198.51.100.24",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"leak": {
						"stage": "",
						"type": "",
						"severity": ""
					}
				},
				{
					"ip": "198.51.100.25",
					"port": "80",
					"protocol": "",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z"
				},
				{
					"ip": "198.51.100.26",
					"port": "",
					"protocol": "",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z"
				},
				{
					"ip": "198.51.100.27",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org"
				},
				{
					"ip": "198.51.100.28",
					"port": "80",
					"protocol": "http",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"service": {
						"software": {
							"name": "nginx",
							"version": "1.18.0"
						}
					},
					"http": {
						"header": {
							"server": "nginx/1.18.0"
						}
					}
				},
				{
					"ip": "198.51.100.29",
					"port": "21",
					"protocol": "ftp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"service": {
						"software": {
							"name": "vsftpd",
							"version": "3.0.3"
						}
					},
					"http": {
						"header": {
							"server": "vsftpd/3.0.3"
						}
					}
				},
				{
					"ip": "invalid-ip-format",
					"port": "80",
					"protocol": "tcp",
					"host": "invalid host name",
					"reverse": "invalid reverse name",
					"time": "2024-01-01T10:00:00Z"
				},
				{
					"ip": "",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"reverse": "example.org",
					"time": "2024-01-01T10:00:00Z"
				},
				{
					"ip": "198.51.100.30",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"http": {}
				},
				{
					"ip": "198.51.100.31",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"http": {
						"header": {
							"content-type": "text/html"
						}
					}
				},
				{
					"ip": "198.51.100.32",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"tags": ["hacked", "", "malware"]
				},
				{
					"ip": "198.51.100.33",
					"port": "443",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"ssl": {
						"certificate": {
							"issuer_name": "Test Issuer",
							"not_after": "2025-01-01T10:00:00Z",
							"domain": ["example.org", "198.51.100.33", "*.", "invalid domain", "*.valid.com"]
						}
					}
				},
				{
					"ip": "198.51.100.34",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"service": {
						"credentials": {}
					}
				},
				{
					"ip": "198.51.100.35",
					"port": "80",
					"protocol": "tcp",
					"host": "example.org",
					"time": "2024-01-01T10:00:00Z",
					"service": {
						"credentials": {
							"noauth": true,
							"key": "secret_key"
						}
					}
				}
			],
			"Leaks": [
				{
					"ip": "invalid-ip",
					"summary": "This is a summary",
					"events": [
						{
							"ip": "198.51.100.99",
							"port": "443",
							"protocol": "tcp",
							"host": "example.net",
							"time": "2024-01-01T10:00:00Z"
						}
					]
				}
			]
		}`)); writeErr != nil {
			panic(writeErr)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	target := schema.Entity{Type: constants.TypeDomain, Value: "example.org"}
	exec := m.getLeakixDomain(target, constants.FuncGetLeakIXDomain, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}
}

func TestEmitCredentials_EmptyBranch(t *testing.T) {
	eg := &eventGroup{
		credentials: []credentialRecord{
			{creds: &CredentialsInfo{}},
		},
	}
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	emitCredentials(exec, eg, &ServiceEvent{}, &schema.EntityRef{}, schema.Entity{}, gen)

	if len(exec.Results) != 1 {
		t.Errorf("Expected 1 result (compromised mark only) for empty credentials, got %d", len(exec.Results))
	}
}
