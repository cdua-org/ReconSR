package anubis

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func overrideBaseURL(t *testing.T, url string) {
	t.Helper()
	orig := baseURL
	baseURL = url + "/"
	t.Cleanup(func() {
		baseURL = orig
	})
}

func setupMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	overrideBaseURL(t, server.URL)
	return server
}

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fnCaps, ok := caps.CustomFunctions[constants.FuncGetDomains]
	if !ok {
		t.Fatal("expected get_domains custom capabilities")
	}

	if len(fnCaps.InputTypes) != 1 || fnCaps.InputTypes[0] != constants.TypeDomain {
		t.Errorf("expected input type domain, got %v", fnCaps.InputTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "portal.example.com"},
		Functions: []string{"invalid_func"},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error == nil {
		t.Error("expected error for unsupported function, got nil")
	}
	if !strings.Contains(*exec.Error, "unsupported function") {
		t.Errorf("expected unsupported function error, got %q", *exec.Error)
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	resolver.HTTPTimeout = 2 * time.Second
	resolver.MaxRetriesHT = 1

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		data, err := os.ReadFile("testdata/response.json")
		if err != nil {
			t.Fatalf("failed to read testdata: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			panic(err)
		}
	}
	server := setupMockServer(t, handler)
	defer server.Close()

	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetDomains},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution")
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %s", *exec.Error)
	}
	if len(exec.Results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(exec.Results))
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestAnubis_Forbidden403(t *testing.T) {
	resolver.HTTPTimeout = 2 * time.Second
	resolver.MaxRetriesHT = 1

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`Access denied`)); err != nil {
			panic(err)
		}
	}
	server := setupMockServer(t, handler)
	defer server.Close()

	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetDomains},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	exec := out.Executions[0]

	if exec.Error != nil {
		t.Fatalf("expected no execution error for 403, got %q", *exec.Error)
	}
	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 result (the Info property), got %d", len(exec.Results))
	}
	res := exec.Results[0]
	if res.Type != constants.TypeInfo {
		t.Errorf("expected type %s, got %s", constants.TypeInfo, res.Type)
	}
	if !strings.Contains(res.Value, "Access denied (HTTP 403) from Anubis API") {
		t.Errorf("expected 403 message in result, got %q", res.Value)
	}
	if exec.RawData != "Access denied" {
		t.Errorf("expected raw data to contain 403 response body, got %q", exec.RawData)
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
