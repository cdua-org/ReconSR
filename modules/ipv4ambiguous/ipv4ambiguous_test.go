package ipv4ambiguous

import (
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestModuleInfo(t *testing.T) {
	m := New()
	if m.Name() != "ipv4ambiguous" {
		t.Errorf("expected module name 'ipv4ambiguous', got %q", m.Name())
	}

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(caps.Functions) == 0 || caps.Functions[0] != "parse_ambiguous" {
		t.Errorf("expected function parse_ambiguous, got %v", caps.Functions)
	}
	if len(caps.InputTypes) == 0 || caps.InputTypes[0] != "ipv4_ambiguous" {
		t.Errorf("expected input type ipv4_ambiguous, got %v", caps.InputTypes)
	}
}

func TestExec_UnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Functions: []string{"unknown_func"},
		Target: schema.Entity{
			Type:  "ipv4_ambiguous",
			Value: "010.0.0.1",
		},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	exec := out.Executions[0]
	if exec.Error == nil || *exec.Error != "unsupported function: unknown_func" {
		t.Errorf("expected 'unsupported function: unknown_func' error, got %v", exec.Error)
	}
}

func TestExec_ParseAmbiguous(t *testing.T) {
	m := New()

	tests := []struct {
		name         string
		input        string
		expectedVals []string
	}{
		{
			name:         "only zero padding (no octal difference)",
			input:        "008.008.008.008",
			expectedVals: []string{"8.8.8.8"},
		},
		{
			name:         "zero padding with octal difference",
			input:        "010.010.010.010",
			expectedVals: []string{"10.10.10.10", "8.8.8.8"},
		},
		{
			name:         "invalid ip",
			input:        "256.256.256.256",
			expectedVals: []string{},
		},
		{
			name:         "all zeros",
			input:        "000.000.000.000",
			expectedVals: []string{"0.0.0.0"},
		},
		{
			name:         "plain standard ip",
			input:        "192.168.1.1",
			expectedVals: []string{"192.168.1.1"},
		},
		{
			name:         "octal overflow",
			input:        "0400.0400.0400.0400",
			expectedVals: []string{},
		},
		{
			name:         "invalid decimal but valid octal posix",
			input:        "0300.0250.001.001",
			expectedVals: []string{"192.168.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := schema.ModuleInput{
				Functions: []string{"parse_ambiguous"},
				Target: schema.Entity{
					Type:  "ipv4_ambiguous",
					Value: tt.input,
				},
			}

			out, err := m.Exec(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			results := out.Executions[0].Results
			if len(results) != len(tt.expectedVals) {
				t.Errorf("expected %d results, got %d for input %s", len(tt.expectedVals), len(results), tt.input)
			}

			for _, expected := range tt.expectedVals {
				found := false
				for _, res := range results {
					if res.Value == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected value %s not found in results", expected)
				}
			}
		})
	}
}
