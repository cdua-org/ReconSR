package ip_metadata

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
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

	if !slices.Contains(caps.Functions, constants.FuncGetPTR) {
		t.Error("expected get_ptr in capabilities")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetIPInfo) {
		t.Error("expected get_ip_info")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetIPAbuseContacts) {
		t.Error("expected get_ip_abuse_contacts")
	}
}

func TestExecUnsupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.2"},
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
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr2.example.com."}, nil
	})

	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.2"},
		Functions: []string{constants.FuncGetPTR},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	if out.Executions[0].Error != nil {
		t.Fatalf("expected no execution error, got: %v", *out.Executions[0].Error)
	}
}

func TestExecAllFunctionsEmptyIP(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target: schema.Entity{Type: constants.TypeIPv4, Value: ""},
		Functions: []string{
			constants.FuncGetPTR,
			constants.FuncGetASN,
			constants.FuncGetTOR,
			constants.FuncGetRBL,
			constants.FuncGetIPInfo,
			constants.FuncGetIPAbuseContacts,
		},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 6 {
		t.Fatalf("expected 6 executions, got %d", len(out.Executions))
	}

	for _, execution := range out.Executions {
		if execution.Error == nil {
			t.Errorf("expected error for function %s due to empty IP, got nil", execution.Function)
		}
	}
}
