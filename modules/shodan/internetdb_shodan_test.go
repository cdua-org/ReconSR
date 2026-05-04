package shodan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestShodanModule_Capabilities(t *testing.T) {
	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.CustomFunctions) != 1 {
		t.Fatalf("expected 1 custom function, got %d", len(caps.CustomFunctions))
	}

	fnCaps, ok := caps.CustomFunctions["get_idb_shodan"]
	if !ok {
		t.Fatal("expected 'get_idb_shodan' capability")
	}

	if fnCaps.Limit != 2 {
		t.Errorf("expected limit 2, got %d", fnCaps.Limit)
	}
	if fnCaps.DelayMs != 1000 {
		t.Errorf("expected delay 1000, got %d", fnCaps.DelayMs)
	}
}

func TestShodanModule_Exec_UnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.1"},
		Functions: []string{"unsupported_function"},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(output.Executions) != 0 {
		t.Errorf("expected 0 executions, got %d", len(output.Executions))
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
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.1"},
		Functions: []string{"get_idb_shodan"},
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

	expectedResultsCount := 1 + 3 + 1 + 1 + 1
	if len(exec.Results) != expectedResultsCount {
		t.Errorf("expected %d results, got %d", expectedResultsCount, len(exec.Results))
	}

	typesCount := make(map[string]int)
	for _, res := range exec.Results {
		typesCount[res.Type]++
	}

	if typesCount["ptr"] != 1 {
		t.Errorf("expected 1 ptr result, got %d", typesCount["ptr"])
	}
	if typesCount["port"] != 3 {
		t.Errorf("expected 3 port results, got %d", typesCount["port"])
	}
	if typesCount["tag"] != 1 {
		t.Errorf("expected 1 tag result, got %d", typesCount["tag"])
	}
	if typesCount["cve"] != 1 {
		t.Errorf("expected 1 cve result, got %d", typesCount["cve"])
	}
	if typesCount["cpe"] != 1 {
		t.Errorf("expected 1 cpe result, got %d", typesCount["cpe"])
	}
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
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.2"},
		Functions: []string{"get_idb_shodan"},
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
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.3"},
		Functions: []string{"get_idb_shodan"},
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
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.4"},
		Functions: []string{"get_idb_shodan"},
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
		Target:    schema.Entity{Type: "ip", Value: "192.0.2.5"},
		Functions: []string{"get_idb_shodan"},
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
