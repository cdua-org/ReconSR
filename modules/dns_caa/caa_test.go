package dns_caa

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

	expectedFuncs := []string{"get_caa"}
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

func TestParseCAARecord(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []schema.ModuleResult
	}{
		{
			name:  "standard issue",
			input: `0 issue "letsencrypt.org"`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 issue "letsencrypt.org"`, Context: "CAA Record"},
				{Type: "domain", Value: "letsencrypt.org", Context: "Authorized CA (issue)", OutOfScope: true},
			},
		},
		{
			name:  "issue with properties",
			input: `0 issue "letsencrypt.org; validationmethods=dns-01"`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 issue "letsencrypt.org; validationmethods=dns-01"`, Context: "CAA Record"},
				{Type: "domain", Value: "letsencrypt.org", Context: "Authorized CA (issue)", OutOfScope: true},
			},
		},
		{
			name:  "issuewild",
			input: `0 issuewild "amazon.com"`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 issuewild "amazon.com"`, Context: "CAA Record"},
				{Type: "domain", Value: "amazon.com", Context: "Authorized CA (issuewild)", OutOfScope: true},
			},
		},
		{
			name:  "iodef mailto",
			input: `0 iodef "mailto:security@example.com"`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 iodef "mailto:security@example.com"`, Context: "CAA Record"},
				{Type: "email", Value: "security@example.com", Context: "CAA Violation Report", OutOfScope: true},
			},
		},
		{
			name:  "iodef http",
			input: `0 iodef "http://example.com/abuse"`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 iodef "http://example.com/abuse"`, Context: "CAA Record"},
				{Type: "url", Value: "http://example.com/abuse", Context: "CAA Violation Report"},
			},
		},
		{
			name:  "invalid format",
			input: `something else`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `something else`, Context: "CAA Record"},
			},
		},
		{
			name:  "hex format RFC 3597",
			input: `\# 21 00 05 69 73 73 75 65 63 6c 6f 75 64 66 6c 61 72 65 2e 63 6f 6d`,
			expected: []schema.ModuleResult{
				{Type: "string", Value: `0 issue "cloudflare.com"`, Context: "CAA Record"},
				{Type: "domain", Value: "cloudflare.com", Context: "Authorized CA (issue)", OutOfScope: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCAARecord(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseCAARecord() mismatch\nGot:  %+v\nWant: %+v", got, tt.expected)
			}
		})
	}
}
