package dns_dmarc

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

	expectedFuncs := []string{"get_dmarc"}
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

func TestFilterDMARC(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid DMARC record",
			input:    []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
			expected: []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
		},
		{
			name:     "multiple records with DMARC",
			input:    []string{"v=DKIM1", "v=DMARC1; p=none", "v=SPF1"},
			expected: []string{"v=DMARC1; p=none"},
		},
		{
			name:     "no DMARC records",
			input:    []string{"v=DKIM1", "v=SPF1"},
			expected: nil,
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "case insensitive - different case not matched",
			input:    []string{"V=DMARC1; p=reject"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("filterDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		expected map[string]string
		name     string
		input    string
	}{
		{
			expected: map[string]string{"v": "DMARC1", "p": "quarantine", "rua": "mailto:dmarc@example.com"},
			name:     "full policy",
			input:    "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": "none"},
			name:     "minimal record",
			input:    "v=DMARC1; p=none",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": "reject", "sp": "quarantine", "aspf": "r"},
			name:     "with sp and aspf",
			input:    "v=DMARC1; p=reject; sp=quarantine; aspf=r",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": ""},
			name:     "empty value",
			input:    "v=DMARC1; p=;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetDMARCDataEmpty(t *testing.T) {
	execution := getDMARCData("nonexistent.domain.invalid")

	if len(execution.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(execution.Results))
	}

	result := execution.Results[0]
	if result.Type != "string" || result.Value != "No DMARC" {
		t.Errorf("expected 'No DMARC' result, got %+v", result)
	}
	if result.Context != "DMARC Records" {
		t.Errorf("expected context 'DMARC Records', got %q", result.Context)
	}
}
