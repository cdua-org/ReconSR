package emailformat

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
	original := baseURL
	baseURL = url
	return func() { baseURL = original }
}

func TestEmailFormatModule_Name(t *testing.T) {
	m := New()
	if m.Name() != moduleName {
		t.Errorf("expected module name %q, got %q", moduleName, m.Name())
	}
}

func TestEmailFormatModule_Capabilities(t *testing.T) {
	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.CustomFunctions) != 1 {
		t.Fatalf("expected 1 custom function, got %d", len(caps.CustomFunctions))
	}

	fnCaps, ok := caps.CustomFunctions[constants.FuncGetEmails]
	if !ok {
		t.Fatalf("expected %q capability", constants.FuncGetEmails)
	}

	if fnCaps.Limit != 1 {
		t.Errorf("expected limit 1, got %d", fnCaps.Limit)
	}
	if fnCaps.DelayMs != 3000 {
		t.Errorf("expected delay 3000, got %d", fnCaps.DelayMs)
	}
}

func TestEmailFormatModule_Exec_UnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "unsupported.example.com"},
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

func TestDecodeCFEmail(t *testing.T) {
	encStr := "5637323b3f3816332e373b263a337835393b"

	dec, ok := decodeCFEmail(encStr)
	if !ok {
		t.Fatal("expected ok")
	}
	if dec != "admin@example.com" {
		t.Errorf("expected %q, got %q", "admin@example.com", dec)
	}

	_, ok = decodeCFEmail("5")
	if ok {
		t.Error("expected false for short string")
	}

	_, ok = decodeCFEmail("562f323b3")
	if ok {
		t.Error("expected false for uneven length")
	}

	_, ok = decodeCFEmail("ZZ2f323b3f")
	if ok {
		t.Error("expected false for invalid hex key")
	}

	_, ok = decodeCFEmail("56ZZ323b3f")
	if ok {
		t.Error("expected false for invalid hex data")
	}
}

func TestGetEmails_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `
			<html><body>
				<a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="5637323b3f3816332e373b263a337835393b">[email&#160;protected]</a>
				<a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="5637323b3f3816332e373b263a337835393b">[email&#160;protected]</a> <!-- duplicate -->
			</body></html>
		`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetEmails},
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

	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 unique result, got %d", len(exec.Results))
	}

	if exec.Results[0].Value != "admin@example.com" {
		t.Errorf("expected %q, got %s", "admin@example.com", exec.Results[0].Value)
	}
}

func TestGetEmails_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(t, w, `Not Found`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "notfound.example.com"},
		Functions: []string{constants.FuncGetEmails},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := output.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %s", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetEmails_HTTPError(t *testing.T) {
	defer withFastRetries(t)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "httperror.example.com"},
		Functions: []string{constants.FuncGetEmails},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := output.Executions[0]
	if exec.Error == nil {
		t.Fatal("expected execution error, got nil")
	}
	if !strings.Contains(*exec.Error, "http status 500") {
		t.Errorf("expected error to contain 'http status 500', got %q", *exec.Error)
	}
}

func TestGetEmails_AbortStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "forbidden.example.com"},
		Functions: []string{constants.FuncGetEmails},
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
