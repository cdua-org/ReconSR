package subdomain_hierarchy

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestGetCapabilities(t *testing.T) {
	m := New()
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	custom, exists := caps.CustomFunctions["decompose"]
	if !exists {
		t.Errorf("expected decompose function in CustomFunctions")
	}
	if len(custom.InputTypes) == 0 || custom.InputTypes[0] != "subdomain" {
		t.Errorf("expected subdomain input type, got %v", custom.InputTypes)
	}
}

func TestHandleData_Decompose(t *testing.T) {
	input := schema.ModuleInput{
		Functions: []string{"decompose"},
		Target: schema.Entity{
			Type:  "subdomain",
			Value: "dev.api.example.com",
		},
	}

	m := New()
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %v", *exec.Error)
	}

	results := exec.Results
	// Expected: example.com, api.example.com
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	var hasOrg, hasParent bool
	for _, res := range results {
		if res.Value == "example.com" {
			hasOrg = true
		}
		if res.Value == "api.example.com" {
			hasParent = true
		}
	}

	if !hasOrg || !hasParent {
		t.Errorf("missing expected results. Org: %v, Parent: %v", hasOrg, hasParent)
	}
}

func TestHandleData_UnsupportedFunction(t *testing.T) {
	input := schema.ModuleInput{
		Functions: []string{"unknown"},
		Target: schema.Entity{
			Type:  "subdomain",
			Value: "example.com",
		},
	}

	m := New()
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := out.Executions[0]
	if exec.Error == nil || *exec.Error != "unsupported function: unknown" {
		t.Errorf("expected 'unsupported function: unknown' error, got %v", exec.Error)
	}
}

func TestHandleData_InvalidDomain(t *testing.T) {
	input := schema.ModuleInput{
		Functions: []string{"decompose"},
		Target: schema.Entity{
			Type: "subdomain",
			// A domain that causes publicsuffix to return an error
			Value: ".co.uk",
		},
	}

	m := New()
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exec := out.Executions[0]
	if exec.Error == nil {
		t.Errorf("expected error for invalid domain, but got none")
	} else if !strings.Contains(exec.RawData, "decompose failed for") {
		t.Errorf("expected RawData to contain 'decompose failed for', got %q", exec.RawData)
	}
}
