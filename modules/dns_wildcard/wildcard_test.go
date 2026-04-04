package dns_wildcard

import (
	"reflect"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedFuncs := []string{"check_wildcard"}
	if !reflect.DeepEqual(caps.Functions, expectedFuncs) {
		t.Errorf("Functions mismatch: got %v, want %v", caps.Functions, expectedFuncs)
	}

	expectedTypes := []string{"domain", "subdomain"}
	if !reflect.DeepEqual(caps.InputTypes, expectedTypes) {
		t.Errorf("InputTypes mismatch: got %v, want %v", caps.InputTypes, expectedTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  "domain",
			Value: "example.com",
		},
		Functions: []string{"invalid_func"},
	}

	output, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Function != "invalid_func" {
		t.Errorf("expected function invalid_func, got %s", exec.Function)
	}

	if exec.Error == nil {
		t.Fatal("expected error, got nil")
	}

	expectedErr := "unsupported function: invalid_func"
	if *exec.Error != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, *exec.Error)
	}
}
