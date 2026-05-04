package anubis

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fnCaps, ok := caps.CustomFunctions["get_domains"]
	if !ok {
		t.Fatal("expected get_domains custom capabilities")
	}

	if len(fnCaps.InputTypes) != 1 || fnCaps.InputTypes[0] != "domain" {
		t.Errorf("expected input type domain, got %v", fnCaps.InputTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: "domain", Value: "example.com"},
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
