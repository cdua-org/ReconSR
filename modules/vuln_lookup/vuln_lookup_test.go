package vuln_lookup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestModule_Capabilities(t *testing.T) {
	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.Functions) != 1 || caps.Functions[0] != constants.FuncGetCirclVuln {
		t.Errorf("expected function %s, got %v", constants.FuncGetCirclVuln, caps.Functions)
	}

	if caps.ModuleConfig == nil {
		t.Fatal("expected ModuleConfig to be set")
	}

	expectedTypes := []string{constants.TypeCVE}
	if len(caps.ModuleConfig.InputTypes) != len(expectedTypes) {
		t.Errorf("expected %d input types, got %v", len(expectedTypes), caps.ModuleConfig.InputTypes)
	}
}

func TestModule_Exec_UnsupportedType(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "example.com",
		},
		Functions: []string{constants.FuncGetCirclVuln},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "unsupported target type") {
		t.Errorf("expected unsupported type error, got %v", exec.Error)
	}
}

func TestModule_Exec_UnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeCVE,
			Value: "CVE-2024-00001",
		},
		Functions: []string{"unknown_function"},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "unsupported function") {
		t.Errorf("expected unsupported function error, got %v", exec.Error)
	}
}

func setupMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var fixture string

		switch {
		case strings.Contains(r.URL.Path, "CVE-2024-38063"):
			fixture = "cve-2024-38063.json"
		case strings.Contains(r.URL.Path, "CVE-2021-44228"):
			fixture = "cve-2021-44228.json"
		case strings.Contains(r.URL.Path, "CVE-2014-0160"):
			fixture = "cve-2014-0160.json"
		case strings.Contains(r.URL.Path, "CVE-2012-3526"):
			fixture = "cve-2012-3526.json"
		case strings.Contains(r.URL.Path, "CVE-2026-41872"):
			fixture = "cve-2026-41872.json"
		case strings.Contains(r.URL.Path, "CVE-ERROR"):
			w.WriteHeader(http.StatusInternalServerError)
			return
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}

		data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", fixture)))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, werr := w.Write(data); werr != nil {
			t.Logf("failed to write response: %v", werr)
		}
	}))
}

func overrideBaseURL(t *testing.T, serverURL string) {
	t.Helper()
	originalBaseURL := circlAPIBaseURL
	circlAPIBaseURL = serverURL
	t.Cleanup(func() { circlAPIBaseURL = originalBaseURL })
}

func overrideRetryDelay(t *testing.T) {
	t.Helper()
	original := resolver.CirclRetryBaseDelay
	resolver.CirclRetryBaseDelay = time.Millisecond
	t.Cleanup(func() { resolver.CirclRetryBaseDelay = original })
}

func TestGetCirclVuln_CVE_WithCNAMetrics(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	tests := []struct {
		cve        string
		expectCWE  bool
		expectSSVC bool
		expectKEV  bool
	}{
		{"CVE-2024-38063", true, true, false},
		{"CVE-2021-44228", true, false, true},
		{"CVE-2014-0160", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.cve, func(t *testing.T) {
			exec := getCirclVuln(context.Background(), constants.TypeCVE, tt.cve, modutil.NewLocalIDGenerator())

			if exec.Error != nil {
				t.Fatalf("unexpected error: %s", *exec.Error)
			}
			if exec.RawData == "" {
				t.Error("expected RawData to be populated")
			}
			requireUniqueLocalIDs(t, exec.Results)

			verifyCVEResults(t, tt.cve, exec.Results, tt.expectCWE, tt.expectSSVC, tt.expectKEV)
		})
	}
}

func TestGetCirclVuln_CVE_NVDFallback(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	tests := []struct {
		name       string
		cve        string
		expectCVSS bool
		expectEPSS bool
		expectCWE  bool
	}{
		{
			name:       "old CVE with NVD CVSS v2 and EPSS",
			cve:        "CVE-2012-3526",
			expectCVSS: true,
			expectEPSS: true,
			expectCWE:  false,
		},
		{
			name:       "fresh CVE with CNA CVSS v3.0 and v4.0",
			cve:        "CVE-2026-41872",
			expectCVSS: true,
			expectEPSS: false,
			expectCWE:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := getCirclVuln(context.Background(), constants.TypeCVE, tt.cve, modutil.NewLocalIDGenerator())

			if exec.Error != nil {
				t.Fatalf("unexpected error: %s", *exec.Error)
			}
			if exec.RawData == "" {
				t.Error("expected RawData to be populated")
			}

			verifyFallbackResults(t, tt.cve, exec.Results, tt.expectCVSS, tt.expectEPSS, tt.expectCWE)
		})
	}
}

func TestGetCirclVuln_CVE2026_MultipleMetricVersions(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	exec := getCirclVuln(context.Background(), constants.TypeCVE, "CVE-2026-41872", modutil.NewLocalIDGenerator())
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}
	requireUniqueLocalIDs(t, exec.Results)

	cvssContexts := make(map[string]bool)
	for _, res := range exec.Results {
		if res.Type == constants.TypeCVSS {
			cvssContexts[res.Context] = true
		}
	}

	if cvssContexts["CVSS 3.0"] {
		t.Error("expected CVSS 3.0 result to be excluded in favor of higher version")
	}
	if !cvssContexts["CVSS 4.0"] {
		t.Error("expected CVSS 4.0 result to be the only CVSS emitted")
	}
}

func verifyCVEResults(t *testing.T, cve string, results []schema.ModuleResult, expectCWE, expectSSVC, expectKEV bool) {
	t.Helper()
	found := make(map[string]bool)

	for _, res := range results {
		found[res.Type] = true
		if res.Type == constants.TypeDescription {
			if res.Source == nil || res.Source.LocalID == 0 {
				t.Error("Description result must have a valid Source.LocalID linking to parent")
			}
		}
	}

	if !found[constants.TypeCVSS] {
		t.Error("expected CVSS result")
	}
	if !found[constants.TypeSummary] {
		t.Error("expected Summary result")
	}
	if expectCWE && !found[constants.TypeCWE] {
		t.Errorf("expected CWE result for %s", cve)
	}
	if expectCWE && !found[constants.TypeDescription] {
		t.Errorf("expected Description result for CWE in %s", cve)
	}
	if expectSSVC && !found[constants.TypeSSVC] {
		t.Errorf("expected SSVC result for %s", cve)
	}
	if expectKEV && !found[constants.TypeKEV] {
		t.Errorf("expected KEV result for %s", cve)
	}
}

func verifyFallbackResults(t *testing.T, cve string, results []schema.ModuleResult, expectCVSS, expectEPSS, expectCWE bool) {
	t.Helper()
	found := make(map[string]bool)

	for _, res := range results {
		found[res.Type] = true
		if res.Type == constants.TypeDescription {
			if res.Source == nil || res.Source.LocalID == 0 {
				t.Error("Description result must have a valid Source.LocalID linking to parent")
			}
		}
	}

	if !found[constants.TypeSummary] {
		t.Error("expected Summary result")
	}
	if expectCVSS && !found[constants.TypeCVSS] {
		t.Errorf("expected CVSS result for %s", cve)
	}
	if expectEPSS && !found[constants.TypeEPSS] {
		t.Errorf("expected EPSS result for %s", cve)
	}
	if expectCWE && !found[constants.TypeCWE] {
		t.Errorf("expected CWE result for %s", cve)
	}
	if expectCWE && !found[constants.TypeDescription] {
		t.Errorf("expected Description result for CWE in %s", cve)
	}
}

func TestGetCirclVuln_NotFound(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	exec := getCirclVuln(context.Background(), constants.TypeCVE, "CVE-UNKNOWN", modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Errorf("did not expect error for 404, got: %s", *exec.Error)
	}

	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}

	if exec.RawData != "" {
		t.Errorf("expected empty RawData for 404, got %q", exec.RawData)
	}
}

func TestGetCirclVuln_ServerError(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)
	overrideRetryDelay(t)

	exec := getCirclVuln(context.Background(), constants.TypeCVE, "CVE-ERROR", modutil.NewLocalIDGenerator())

	if exec.Error == nil {
		t.Fatal("expected error for 500 status code")
	}

	if !strings.Contains(*exec.Error, "http 500") {
		t.Errorf("expected 'http 500' error, got %s", *exec.Error)
	}
}

func TestIsValidCWE(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"CWE-295", true},
		{"CWE-191", true},
		{"CWE-79", true},
		{"NVD-CWE-noinfo", false},
		{"NVD-CWE-Other", false},
		{"CWE-", false},
		{"", false},
		{"CWE-abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidCWE(tt.input)
			if got != tt.want {
				t.Errorf("isValidCWE(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	gen := modutil.NewLocalIDGenerator()
	exec := getCirclVuln(context.Background(), constants.TypeCVE, "CVE-2024-38063", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
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
