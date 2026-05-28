package ip_metadata

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestGetPTRDataMockedResult(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr1.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected results, got none")
	}
	if res.Results[0].Value != "ptr1.example.com" {
		t.Errorf("expected %q, got %q", "ptr1.example.com", res.Results[0].Value)
	}
}

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

func TestGetPTRData(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr3.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected at least one PTR record")
	}
	if res.Results[0].Type != constants.TypeSubdomain {
		t.Errorf("expected type %q, got %q", constants.TypeSubdomain, res.Results[0].Type)
	}
	if !slices.Contains(res.Results[0].Tags, constants.TagReverseIP) {
		t.Errorf("expected tag %q, got %v", constants.TagReverseIP, res.Results[0].Tags)
	}
}

func TestGetPTRDataInvalidPTRHostname(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"invalid ptr hostname."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.Results[0].Type != constants.TypePTR {
		t.Errorf("expected type %q, got %q", constants.TypePTR, res.Results[0].Type)
	}
	if res.Results[0].Category != constants.CategoryProperty {
		t.Errorf("expected category %q, got %q", constants.CategoryProperty, res.Results[0].Category)
	}
	if len(res.Results[0].Tags) > 0 {
		t.Errorf("expected no tags for invalid PTR hostname, got %v", res.Results[0].Tags)
	}
}

func TestGetPTRDataNoHost(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return nil, nil
	})

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

func TestGetPTRDataTimeout(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return nil, context.DeadlineExceeded
	})

	res := getPTRData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_PTR(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr4.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}
