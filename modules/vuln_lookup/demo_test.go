package vuln_lookup

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestDemoMode_CPE(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := New()
	mod, ok := m.(*module)
	if !ok {
		t.Fatal("failed to cast module")
	}
	mod.apiKey = demoIndicator

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeCPE,
			Value: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
		},
		Functions: []string{constants.FuncSearchCirclCPE},
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
		t.Fatalf("unexpected error in demo mode: %s", *exec.Error)
	}

	cveCount := countCVEs(exec.Results)
	if cveCount == 0 {
		t.Errorf("expected >0 CVEs in demo mode, got %d", cveCount)
	}
}

func TestDemoMode_CVE(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := New()
	mod, ok := m.(*module)
	if !ok {
		t.Fatal("failed to cast module")
	}
	mod.apiKey = demoIndicator

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeCVE,
			Value: "CVE-2024-38063",
		},
		Functions: []string{constants.FuncEnrichCirclCVE},
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
		t.Fatalf("unexpected error in demo mode: %s", *exec.Error)
	}

	if len(exec.Results) == 0 {
		t.Error("expected results in demo mode")
	}
}
