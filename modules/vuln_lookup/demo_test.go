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
	mod.demoCPEFired.Store(false)

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeCPE,
			Value: "cpe:2.3:a:nginx:nginx:1.24.1:*:*:*:*:*:*:*",
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

	input2 := input
	input2.Target.Value = "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"

	out2, err2 := m.Exec(input2)
	if err2 != nil {
		t.Fatalf("unexpected error on second call: %v", err2)
	}
	if len(out2.Executions) != 1 || out2.Executions[0].Error != nil {
		t.Fatalf("expected no errors on second call")
	}
	if len(out2.Executions[0].Results) != 0 {
		t.Errorf("expected 0 results on second call, got %d", len(out2.Executions[0].Results))
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
	mod.demoCVEFired.Store(false)

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeCVE,
			Value: "CVE-2024-38065",
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

	input2 := input
	input2.Target.Value = "CVE-2024-38064"

	out2, err2 := m.Exec(input2)
	if err2 != nil {
		t.Fatalf("unexpected error on second call: %v", err2)
	}
	if len(out2.Executions) != 1 || out2.Executions[0].Error != nil {
		t.Fatalf("expected no errors on second call")
	}
	if len(out2.Executions[0].Results) != 0 {
		t.Errorf("expected 0 results on second call, got %d", len(out2.Executions[0].Results))
	}
}
