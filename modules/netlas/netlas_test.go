package netlas

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetlasModuleName(t *testing.T) {
	m := &netlasModule{}
	if m.Name() != "netlas" {
		t.Fatalf("expected netlas, got %s", m.Name())
	}
}

func TestNetlasModuleCapabilities(t *testing.T) {
	m := &netlasModule{apiKey: ""}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(caps.CustomFunctions) != 0 {
		t.Errorf("expected 0 functions without API key, got %d", len(caps.CustomFunctions))
	}

	m = &netlasModule{apiKey: testAPIKey}

	resolver.NetlasScanSubdomains = false
	caps, err = m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(caps.CustomFunctions) == 0 {
		t.Errorf("expected >0 functions with API key")
	}

	resolver.NetlasScanSubdomains = true
	caps, err = m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(caps.CustomFunctions) == 0 {
		t.Errorf("expected >0 functions with API key")
	}
}

func TestNetlasDemoMode(t *testing.T) {
	m := &netlasModule{apiKey: demoIndicator}

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "demo.example.edu"},
		Functions: []string{constants.FuncGetNetlasDomain},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("expected no error, got %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Errorf("expected results from demo mode, got 0")
	}

	foundDemo := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeDomain && res.Value == "demo.example.edu" {
			foundDemo = true
		}
	}
	if !foundDemo {
		t.Errorf("expected demo response to parse example.com domain")
	}

	out2, err2 := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "another.example.edu"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err2 != nil {
		t.Fatalf("unexpected err2: %v", err2)
	}
	if len(out2.Executions) > 0 && len(out2.Executions[0].Results) > 0 {
		t.Errorf("expected no results on second demo call")
	}
}

func TestNetlasDemoMode_IP(t *testing.T) {
	m := &netlasModule{apiKey: demoIndicator}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	exec := out.Executions[0]
	hasDemoTarget := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeIPv4 && res.Value == testIP198 {
			hasDemoTarget = true
			break
		}
	}
	if !hasDemoTarget {
		t.Errorf("expected demo IP to be processed")
	}

	out2, err2 := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err2 != nil {
		t.Fatalf("unexpected err: %v", err2)
	}
	if len(out2.Executions[0].Results) > 0 {
		t.Errorf("expected no results on second demo call")
	}
}
func TestNetlasQuotaAndInvalidKey(t *testing.T) {
	m := &netlasModule{apiKey: testAPIKey}
	server := setupMockServer(t, []byte(`{}`))
	defer server.Close()
	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	m.keyInvalid.Store(true)
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example1.net"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec := out.Executions[0]
	assertHasResult(t, exec.Results, constants.TypeInfo, "Netlas API Key is invalid or forbidden", "")

	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.10"},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec = out.Executions[0]
	assertHasResult(t, exec.Results, constants.TypeInfo, "Netlas API Key is invalid or forbidden", "")

	m.keyInvalid.Store(false)

	m.quotaBlocked.Store(true)
	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.org"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec = out.Executions[0]
	assertHasResult(t, exec.Results, constants.TypeInfo, "Netlas Quota Exhausted (Not Enough Coins)", "")

	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.11"},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec = out.Executions[0]
	assertHasResult(t, exec.Results, constants.TypeInfo, "Netlas Quota Exhausted (Not Enough Coins)", "")

	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "test.example.com"},
		Functions: []string{"invalid_func"},
	})
	if err != nil {
		t.Fatalf("unexpected global error: %v", err)
	}
	exec = out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "unsupported function") {
		t.Fatalf("expected unsupported function error, got %v", exec.Error)
	}
}

func TestNetlasInvalidJSON(t *testing.T) {
	server := setupMockServer(t, []byte(`{invalid_json`))
	defer server.Close()

	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	m := &netlasModule{apiKey: testAPIKey}

	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "invalid.example.net"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec := out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "parse json") {
		t.Fatalf("expected parse json error, got %v", exec.Error)
	}

	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec = out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "parse json") {
		t.Fatalf("expected parse json error, got %v", exec.Error)
	}
}

func TestNetlasEmptyRootIP(t *testing.T) {
	server := setupMockServer(t, []byte(`{"ip": ""}`))
	defer server.Close()

	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	m := &netlasModule{apiKey: testAPIKey}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "127.0.0.1"},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if len(out.Executions[0].Results) > 0 {
		t.Errorf("expected no results for empty root IP")
	}
}

func TestUnmarshalJSONErrors(t *testing.T) {
	var resp netlasResponse
	err := resp.UnmarshalJSON([]byte(`{"type": "domain", "whois": [1, 2, 3]}`))
	if err != nil {
		t.Fatalf("expected no error from main struct unmarshal, got %v", err)
	}
	if resp.Whois != nil {
		t.Errorf("expected whois to be nil on unmarshal error")
	}

	err = resp.UnmarshalJSON([]byte(`{invalid`))
	if err == nil {
		t.Errorf("expected error on invalid json")
	}

	var ipResp netlasIPResponse
	err = ipResp.UnmarshalJSON([]byte(`{"whois": "invalid"}`))
	if err != nil {
		t.Fatalf("expected no error from ipResp main unmarshal, got %v", err)
	}
	if ipResp.Whois != nil {
		t.Errorf("expected whois to be nil on unmarshal error")
	}

	err = ipResp.UnmarshalJSON([]byte(`{invalid`))
	if err == nil {
		t.Errorf("expected error on invalid json")
	}

	var tag netlasSoftwareTag
	err = tag.UnmarshalJSON([]byte(`{invalid`))
	if err == nil {
		t.Errorf("expected error on invalid json for tag")
	}
	err = tag.UnmarshalJSON([]byte(`"valid_but_not_object"`))
	if err == nil {
		t.Errorf("expected error when tag is not object")
	}
}

func TestUnmarshalJSONTypeErrors(t *testing.T) {
	var resp netlasResponse
	err := resp.UnmarshalJSON([]byte(`{"dns": {"a": 123}}`))
	if err == nil {
		t.Errorf("expected error on dns type mismatch")
	}

	var ipResp netlasIPResponse
	err = ipResp.UnmarshalJSON([]byte(`{"geo": {"country": 123}}`))
	if err == nil {
		t.Errorf("expected error on geo type mismatch")
	}

	var tag netlasSoftwareTag
	err = tag.UnmarshalJSON([]byte(`[]`))
	if err == nil {
		t.Errorf("expected error on array to map unmarshal")
	}

	err = resp.UnmarshalJSON([]byte(`{"type": "domain", "whois": {"server": 123}}`))
	if err == nil {
		t.Errorf("expected error on domain whois type mismatch")
	}
}

func TestDemoJSONErrors(t *testing.T) {
	oldDomain := demoDomainResponses
	oldIP := demoIPResponses
	defer func() {
		demoDomainResponses = oldDomain
		demoIPResponses = oldIP
	}()

	demoDomainResponses = []byte(`{invalid`)
	demoIPResponses = []byte(`{invalid`)

	m := &netlasModule{apiKey: demoIndicator}
	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "demo.example.org"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err != nil {
		t.Fatalf("unexpected global error: %v", err)
	}
	exec := out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "demo parse json") {
		t.Errorf("expected demo parse json error, got %v", exec.Error)
	}

	out, err = m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.13"},
		Functions: []string{constants.FuncGetNetlasIP},
	})
	if err != nil {
		t.Fatalf("unexpected global error: %v", err)
	}
	exec = out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "demo parse json") {
		t.Errorf("expected demo parse json error, got %v", exec.Error)
	}
}

func TestExtractCVSS(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		name     string
		cve      *netlasCVE
		expected string
	}{
		{"Both", &netlasCVE{Severity: 8.5, BaseScore: 8.8}, "8.5 / 8.8"},
		{"SeverityOnly", &netlasCVE{Severity: 8.5}, "8.5"},
		{"BaseScoreOnly", &netlasCVE{BaseScore: 8.8}, "8.8"},
		{"Neither", &netlasCVE{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := modutil.NewExecution("test")
			ref := &schema.EntityRef{Type: constants.TypeCVE, Value: "CVE-1234-5678"}
			cvssRef := extractCVSS(&exec, tt.cve, ref, gen)

			assertExtractCVSSResult(t, &exec, tt.expected, cvssRef, ref)
		})
	}
}

func assertExtractCVSSResult(t *testing.T, exec *schema.ModuleExecution, expected string, cvssRef, origRef *schema.EntityRef) {
	t.Helper()
	if expected == "" {
		if cvssRef != origRef {
			t.Errorf("expected original ref, got %v", cvssRef)
		}
		if len(exec.Results) != 0 {
			t.Errorf("expected 0 results, got %d", len(exec.Results))
		}
		return
	}
	if cvssRef == nil {
		t.Fatalf("expected ref, got nil")
	}
	if cvssRef.Value != expected {
		t.Errorf("expected ref value %s, got %s", expected, cvssRef.Value)
	}
	if len(exec.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(exec.Results))
	} else if exec.Results[0].Value != expected {
		t.Errorf("expected result value %s, got %s", expected, exec.Results[0].Value)
	}
}

func TestExtractCVSS_NoScoreMetrics(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	cveRef := &schema.EntityRef{Type: constants.TypeCVE, Value: "CVE-TEST-METRICS"}

	cve := &netlasCVE{AttackVector: "NETWORK"}

	cvssRef := extractCVSS(exec, cve, cveRef, gen)
	if cvssRef == nil {
		t.Fatal("expected CVSS ref")
	}
	if cvssRef.Value != "Metrics Available" {
		t.Errorf("expected 'Metrics Available', got %s", cvssRef.Value)
	}
}

func TestExtractPortFromURI(t *testing.T) {
	tests := []struct {
		uri  string
		port int
	}{
		{"http://example.net:8080/path", 8080},
		{"http://example.net:80", 80},
		{"http://example.net/noport", 0},
		{"http://example.net:notaport/path", 0},
		{"example.net", 0},
	}
	for _, tt := range tests {
		if got := extractPortFromURI(tt.uri); got != tt.port {
			t.Errorf("extractPortFromURI(%q) = %d, want %d", tt.uri, got, tt.port)
		}
	}
}

func TestNetlasEmptyRootDomain(t *testing.T) {
	m := &netlasModule{apiKey: testAPIKey}
	server := setupMockServer(t, []byte(`{"domain": ""}`))
	defer server.Close()
	originalURL := netlasAPIBaseURL
	netlasAPIBaseURL = server.URL
	defer func() { netlasAPIBaseURL = originalURL }()

	out, err := m.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "empty.com"},
		Functions: []string{constants.FuncGetNetlasDomain},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Executions[0].Results) > 0 {
		t.Errorf("expected no results for empty domain, got %d", len(out.Executions[0].Results))
	}
}

func TestCommonEdgeCases(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	pRef := &schema.EntityRef{Type: constants.TypeDomain, Value: "example.net"}

	sw := &netlasSoftware{
		Tags: []netlasSoftwareTag{
			{Name: "", FullName: ""},
			{Name: "nginx", FullName: "", Version: "1.0"},
			{Name: "mysql", Category: []string{"database"}},
		},
	}
	sRefs := parseSoftwareTags(exec, sw, pRef, gen)
	if len(sRefs) == 0 {
		t.Errorf("expected some refs")
	}

	cves := &netlasSoftware{
		CVE: []netlasCVE{
			{Name: "CVE-123", MatchType: "cpe", MatchProduct: "nonexistent"},
		},
	}
	parseSoftwareCVEs(exec, cves, sRefs, pRef, pRef, gen)

	parseNetlasDomains(exec, 2, []string{""}, "", pRef, gen)

	ParseEmails(exec, []string{"   ", "whois@example.com"}, "test", "test", false, pRef, gen)

	tag := &netlasSoftwareTag{}
	if err := tag.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Errorf("expected error on invalid JSON map")
	}
}

func TestExecuteHTTPRequest_ReadBodyError(t *testing.T) {
	m := &netlasModule{apiKey: "fake-key-test"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
	}))
	defer server.Close()

	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	_, _, _, ok := m.executeHTTPRequest(exec, server.URL, 0, "test", gen)
	if ok {
		t.Errorf("expected executeHTTPRequest to fail on body read")
	}
}
