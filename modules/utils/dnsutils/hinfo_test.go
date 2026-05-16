package dnsutils

import (
	"testing"
)

func TestParseHINFO(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		expectedCPU string
		expectedOS  string
	}{
		{
			name:        "valid standard",
			raw:         "\"INTEL-386\" \"UNIX\"",
			expectedCPU: "INTEL-386",
			expectedOS:  "UNIX",
		},
		{
			name:        "valid with spaces in OS",
			raw:         "\"ARM\" \"Ubuntu Linux\"",
			expectedCPU: "ARM",
			expectedOS:  "Ubuntu Linux",
		},
		{
			name:        "no quotes",
			raw:         "AMD64 Windows",
			expectedCPU: "AMD64",
			expectedOS:  "Windows",
		},
		{
			name:        "invalid single string",
			raw:         "\"INTEL-386\"",
			expectedCPU: "",
			expectedOS:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseHINFO(tt.raw)
			if tt.expectedCPU == "" {
				if result != nil {
					t.Fatalf("expected nil for invalid record, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected result, got nil")
			}
			if result.CPU != tt.expectedCPU {
				t.Errorf("expected CPU %q, got %q", tt.expectedCPU, result.CPU)
			}
			if result.OS != tt.expectedOS {
				t.Errorf("expected OS %q, got %q", tt.expectedOS, result.OS)
			}
			if result.Formatted != tt.raw {
				t.Errorf("expected Formatted %q, got %q", tt.raw, result.Formatted)
			}
		})
	}
}
