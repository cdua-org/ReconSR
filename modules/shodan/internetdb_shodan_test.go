package shodan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func writeTestResponse(t *testing.T, w http.ResponseWriter, data string) {
	t.Helper()
	if _, err := w.Write([]byte(data)); err != nil {
		t.Errorf("failed to write test response: %v", err)
	}
}

func withFastRetries(t *testing.T) func() {
	t.Helper()
	origDelay := resolver.RetryBaseDelay
	origTimeout := resolver.Timeout
	origHTTPTimeout := resolver.HTTPTimeout
	resolver.RetryBaseDelay = 10 * time.Millisecond
	resolver.Timeout = 2 * time.Second
	resolver.HTTPTimeout = 2 * time.Second
	return func() {
		resolver.RetryBaseDelay = origDelay
		resolver.Timeout = origTimeout
		resolver.HTTPTimeout = origHTTPTimeout
	}
}

func withMockHost(t *testing.T, url string) func() {
	t.Helper()
	original := internetDBHost
	internetDBHost = url
	return func() { internetDBHost = original }
}

func TestShodanModule_Name(t *testing.T) {
	m := New()
	if m.Name() != "shodan" {
		t.Errorf("expected module name 'shodan', got %q", m.Name())
	}
}

func TestShodanModule_CapabilitiesWithoutAPIKey(t *testing.T) {
	m := &shodanModule{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.CustomFunctions) != 1 {
		t.Fatalf("expected 1 custom function, got %d", len(caps.CustomFunctions))
	}

	fnCaps, ok := caps.CustomFunctions[constants.FuncGetIDBShodan]
	if !ok {
		t.Fatal("expected 'get_idb_shodan' capability")
	}

	if fnCaps.Limit != 2 {
		t.Errorf("expected limit 2, got %d", fnCaps.Limit)
	}
	if fnCaps.DelayMs != 1000 {
		t.Errorf("expected delay 1000, got %d", fnCaps.DelayMs)
	}
	if _, ok := caps.CustomFunctions[constants.FuncGetShodanAPIIP]; ok {
		t.Fatal("did not expect 'get_shodan_api_ip' capability without API key")
	}
	if _, ok := caps.CustomFunctions[constants.FuncGetShodanAPIDomain]; ok {
		t.Fatal("did not expect 'get_shodan_api_domain' capability without API key")
	}
}

func TestShodanModule_CapabilitiesWithAPIKey(t *testing.T) {
	m := &shodanModule{apiKey: shodanTestAPIKey()}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.CustomFunctions) != 2 {
		t.Fatalf("expected 2 custom functions, got %d", len(caps.CustomFunctions))
	}

	if _, ok := caps.CustomFunctions[constants.FuncGetIDBShodan]; ok {
		t.Fatal("did not expect 'get_idb_shodan' capability with API key")
	}

	ipCaps, ok := caps.CustomFunctions[constants.FuncGetShodanAPIIP]
	if !ok {
		t.Fatal("expected 'get_shodan_api_ip' capability")
	}
	if ipCaps.Limit != 1 {
		t.Errorf("expected IP limit 1, got %d", ipCaps.Limit)
	}
	if len(ipCaps.InputTypes) != 2 || ipCaps.InputTypes[0] != constants.TypeIPv4 || ipCaps.InputTypes[1] != constants.TypeIPv6 {
		t.Errorf("unexpected IP input types: %v", ipCaps.InputTypes)
	}

	domainCaps, ok := caps.CustomFunctions[constants.FuncGetShodanAPIDomain]
	if !ok {
		t.Fatal("expected 'get_shodan_api_domain' capability")
	}
	if domainCaps.Limit != 1 {
		t.Errorf("expected domain limit 1, got %d", domainCaps.Limit)
	}
	if len(domainCaps.InputTypes) != 1 || domainCaps.InputTypes[0] != constants.TypeDomain {
		t.Errorf("unexpected domain input types: %v", domainCaps.InputTypes)
	}
}

func TestShodanModule_CapabilitiesWithScanSubdomains(t *testing.T) {
	resolver.ShodanScanSubdomains = true
	defer func() { resolver.ShodanScanSubdomains = false }()

	m := &shodanModule{apiKey: shodanTestAPIKey()}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	domainCaps, ok := caps.CustomFunctions[constants.FuncGetShodanAPIDomain]
	if !ok {
		t.Fatal("expected 'get_shodan_api_domain' capability")
	}

	if len(domainCaps.InputTypes) != 2 || domainCaps.InputTypes[0] != constants.TypeDomain || domainCaps.InputTypes[1] != constants.TypeSubdomain {
		t.Errorf("unexpected domain input types with ShodanScanSubdomains=true: %v", domainCaps.InputTypes)
	}
}

func TestShodanModule_Exec_UnsupportedFunction(t *testing.T) {
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: internetDBTestIPv4()},
		Functions: []string{"unsupported_function"},
	}

	m := &shodanModule{}
	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Error == nil {
		t.Error("expected error to be set for unsupported function")
	} else if !strings.Contains(*exec.Error, "unsupported function") {
		t.Errorf("expected error to contain 'unsupported function', got %q", *exec.Error)
	}
}

func TestShodanModule_Exec_APIKeyGatesFunctions(t *testing.T) {
	keylessModule := &shodanModule{}
	keylessOutput, err := keylessModule.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: internetDBTestIPv4()},
		Functions: []string{constants.FuncGetShodanAPIIP},
	})
	if err != nil {
		t.Fatalf("unexpected error for keyless module: %v", err)
	}
	if len(keylessOutput.Executions) != 1 {
		t.Fatalf("expected 1 execution for keyless module, got %d", len(keylessOutput.Executions))
	}
	if keylessOutput.Executions[0].Error == nil || !strings.Contains(*keylessOutput.Executions[0].Error, "unsupported function") {
		t.Fatalf("expected unsupported function error for keyless API call, got %+v", keylessOutput.Executions[0])
	}

	apiModule := &shodanModule{apiKey: shodanTestAPIKey()}
	apiOutput, err := apiModule.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: internetDBTestIPv4()},
		Functions: []string{constants.FuncGetIDBShodan},
	})
	if err != nil {
		t.Fatalf("unexpected error for API module: %v", err)
	}
	if len(apiOutput.Executions) != 1 {
		t.Fatalf("expected 1 execution for API module, got %d", len(apiOutput.Executions))
	}
	if apiOutput.Executions[0].Error == nil || !strings.Contains(*apiOutput.Executions[0].Error, "unsupported function") {
		t.Fatalf("expected unsupported function error for InternetDB call with API key, got %+v", apiOutput.Executions[0])
	}
}

func TestGetInternetDB_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{
			"cpes": ["cpe:/a:example:test"],
			"hostnames": ["test.example.com"],
			"ip": "192.0.2.1",
			"ports": [53, 80, 443],
			"tags": ["dns"],
			"vulns": ["CVE-1234-5678"]
		}`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: internetDBTestIPv4()},
		Functions: []string{constants.FuncGetIDBShodan},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %s", *exec.Error)
	}

	expectedResultsCount := 1 + 3 + 1 + 1 + 1 + 1
	if len(exec.Results) != expectedResultsCount {
		t.Errorf("expected %d results, got %d", expectedResultsCount, len(exec.Results))
	}

	typesCount := make(map[string]int)
	for _, res := range exec.Results {
		typesCount[res.Type]++
	}

	if typesCount[constants.TypeSubdomain] != 1 {
		t.Errorf("expected 1 reverse IP subdomain result, got %d", typesCount[constants.TypeSubdomain])
	}
	if typesCount[constants.TypePTR] != 0 {
		t.Errorf("expected 0 ptr results for valid hostnames, got %d", typesCount[constants.TypePTR])
	}
	if typesCount["port"] != 3 {
		t.Errorf("expected 3 port results, got %d", typesCount["port"])
	}
	if typesCount[constants.TypeTag] != 1 {
		t.Errorf("expected 1 tag result, got %d", typesCount[constants.TypeTag])
	}
	if typesCount[constants.TypeCVE] != 1 {
		t.Errorf("expected 1 cve result, got %d", typesCount[constants.TypeCVE])
	}
	if typesCount[constants.TypeCPE] != 1 {
		t.Errorf("expected 1 cpe result, got %d", typesCount[constants.TypeCPE])
	}
	if typesCount[constants.TypeIPv4] != 1 {
		t.Errorf("expected 1 ipv4 result, got %d", typesCount[constants.TypeIPv4])
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestGetInternetDB_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(t, w, `{"detail": "No information available"}`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: "192.0.2.2"},
		Functions: []string{constants.FuncGetIDBShodan},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error for 404: %s", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetInternetDB_HTTPError(t *testing.T) {
	defer withFastRetries(t)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: "192.0.2.3"},
		Functions: []string{constants.FuncGetIDBShodan},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Error == nil {
		t.Fatal("expected execution error, got nil")
	}
	if !strings.Contains(*exec.Error, "http status 500") {
		t.Errorf("expected error to contain 'http status 500', got %q", *exec.Error)
	}
}

func TestGetInternetDB_AbortStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: "192.0.2.4"},
		Functions: []string{constants.FuncGetIDBShodan},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := output.Executions[0]
	if exec.Error == nil {
		t.Fatal("expected execution error, got nil")
	}
	if !strings.Contains(*exec.Error, "http status 403") {
		t.Errorf("expected error to contain 'http status 403', got %q", *exec.Error)
	}
}

func TestGetInternetDB_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{invalid json`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIP, Value: "192.0.2.5"},
		Functions: []string{constants.FuncGetIDBShodan},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := output.Executions[0]
	if exec.Error == nil {
		t.Fatal("expected execution error, got nil")
	}
	if !strings.Contains(*exec.Error, "unmarshal json") {
		t.Errorf("expected error to contain 'unmarshal json', got %q", *exec.Error)
	}
}
