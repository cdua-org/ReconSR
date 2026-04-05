package dns

import (
	"slices"
	"testing"

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

	if !slices.Contains(caps.Functions, "get_ip") {
		t.Error("expected get_ip in capabilities")
	}
}

func TestExecUnsupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: "domain", Value: "example.com"},
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

func TestGetIPData(t *testing.T) {
	// A basic integration test to see if fallback to standard resolver or DoH works.
	// We execute getIPData and expect results.
	res := getIPData("example.com")

	switch {
	case res.Error != nil:
		// Log the error but don't fail immediately if it's a network issue in CI,
		// though ideally it should resolve example.com.
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one IP for example.com")
	case res.Results[0].Type != "ip":
		t.Errorf("expected type 'ip', got '%s'", res.Results[0].Type)
	}
}
