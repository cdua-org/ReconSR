package ip_metadata

import (
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(caps.Functions) == 0 {
		t.Fatal("expected functions, got none")
	}

	if !slices.Contains(caps.Functions, "get_ptr") {
		t.Error("expected get_ptr in capabilities")
	}
}

func TestExecUnsupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: "ipv4", Value: "8.8.8.8"},
		Functions: []string{"unknown_func"},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	if out.Executions[0].Error == nil {
		t.Error("expected error for unsupported function")
	}
}

func TestModuleName(t *testing.T) {
	mod := New()
	if mod.Name() != "ip_metadata" {
		t.Errorf("expected name 'ip_metadata', got '%s'", mod.Name())
	}
}

func TestExecSupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: "ipv4", Value: "8.8.8.8"},
		Functions: []string{"get_ptr"},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	if out.Executions[0].Function != "get_ptr" {
		t.Errorf("expected function get_ptr, got %s", out.Executions[0].Function)
	}
}

func TestGetPTRData(t *testing.T) {
	res := getPTRData("8.8.8.8")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one PTR record for 8.8.8.8")
	case res.Results[0].Type != "domain":
		t.Errorf("expected type 'domain', got '%s'", res.Results[0].Type)
	}
}

func TestGetPTRDataNoHost(t *testing.T) {
	res := getPTRData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for non-existent PTR, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetPTRDataInvalidIP(t *testing.T) {
	res := getPTRData("invalid-ip")
	if res.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestGetPTRDataDebug(t *testing.T) {
	t.Log("Testing debug output")
	resolver.Options["Debug"] = "true"
	defer func() { resolver.Options["Debug"] = "false" }()

	// Trigger debug lines for success, nxdomain, and invalid
	getPTRData("8.8.8.8")
	getPTRData("192.0.2.1")
	getPTRData("invalid")
}

func TestGetPTRDataTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	res := getPTRData("8.8.8.8")
	if res.Error == nil {
		t.Error("expected network error/timeout with 1ns timeout, got nil")
	}
}
