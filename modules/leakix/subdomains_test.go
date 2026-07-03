package leakix

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestLeakixSubdomains(t *testing.T) {
	teardown := newTestServer(t, "subdomains_response.json")
	defer teardown()

	m := &leakixModule{
		apiKey: testKey,
	}

	target := schema.Entity{Type: constants.TypeDomain, Value: testDomain}
	exec := m.getLeakixSubdomains(target, constants.FuncGetLeakIXSubdomains, modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}

	if len(exec.Results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	assertSubdomains(t, exec.Results)
	checkLocalIDs(t, exec.Results)
}

func assertSubdomains(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	var hasSub1, hasSub2, hasDistinctIPs, hasLastSeen bool
	for _, res := range results {
		if res.Type == constants.TypeSubdomain && res.Value == "www.example.com" {
			hasSub1 = true
		}
		if res.Type == constants.TypeDate && res.Value == "Last Seen: 2026-05-20" {
			hasLastSeen = true
		}
		if res.Type == constants.TypeSubdomain && res.Value == "staging.example.com" {
			hasSub2 = true
		}
		if res.Type == constants.TypeInfo && res.Value == "Distinct IPs: 2" {
			hasDistinctIPs = true
		}
	}

	if !hasSub1 || !hasSub2 {
		t.Errorf("Expected subdomains www.example.com and staging.example.com")
	}
	if !hasDistinctIPs {
		t.Errorf("Expected distinct IPs info")
	}
	if !hasLastSeen {
		t.Errorf("Expected Last Seen info")
	}
}

func TestLeakixSubdomains_BlockedAPIKey(t *testing.T) {
	m := &leakixModule{apiKey: testKey}
	m.blockedStatus.Store(401)
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Executions[0].Results) == 0 || !strings.Contains(out.Executions[0].Results[0].Value, "API key invalid") {
		t.Errorf("Expected blocked message, got %v", out.Executions[0].Results)
	}

	m.blockedStatus.Store(403)
	out2, err2 := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err2 != nil {
		t.Fatal(err2)
	}
	if len(out2.Executions[0].Results) == 0 || !strings.Contains(out2.Executions[0].Results[0].Value, "API access blocked (HTTP 403)") {
		t.Errorf("Expected HTTP 403 blocked message, got %v", out2.Executions[0].Results)
	}
}

func TestLeakixSubdomains_EmptyTarget(t *testing.T) {
	m := &leakixModule{apiKey: testKey}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: ""},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "empty target") {
		t.Error("Expected empty target error")
	}
}

func TestLeakixSubdomains_NetworkError(t *testing.T) {
	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = "http://127.0.0.3:0"
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executions[0].Error == nil {
		t.Error("Expected network error")
	}
}

func TestLeakixSubdomains_Non200Status(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, werr := w.Write([]byte(`{}`)); werr != nil {
			panic(werr)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "non-200") {
		t.Error("Expected non-200 error")
	}
}

func TestLeakixSubdomains_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, werr := w.Write([]byte(`{"broken":`)); werr != nil {
			panic(werr)
		}
	}))
	defer ts.Close()

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	defer func() { leakixAPIBaseURL = originalURL }()

	m := &leakixModule{apiKey: testKey}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: testDomain},
		Functions: []string{constants.FuncGetLeakIXSubdomains},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Executions[0].Error == nil || !strings.Contains(*out.Executions[0].Error, "parse json") {
		t.Error("Expected JSON parse error")
	}
}

func TestFormatLeakixSubdomains_InvalidDomainsFilter(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	resp := []SubdomainResponse{
		{Subdomain: ""},
		{Subdomain: "invalid format space"},
	}
	formatLeakixSubdomains(exec, resp, testDomain, gen)
	if len(exec.Results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(exec.Results))
	}
}
