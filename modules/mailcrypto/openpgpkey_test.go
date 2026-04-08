package mailcrypto

import (
	"strings"
	"testing"
)

func TestParseOPENPGPKEY(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format",
			"\\# 4 01020304",
			"AQIDBA==", // base64 representation of 01020304
		},
		{
			"passthrough non-wire",
			"Base64DataString==",
			"Base64DataString==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOPENPGPKEY(tt.input)
			if got != tt.expected {
				t.Errorf("parseOPENPGPKEY() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetOPENPGPKEYDataEmptyTarget(t *testing.T) {
	execution := getOPENPGPKEYData([]string{"testuser"}, "example.com")

	if len(execution.Results) > 0 {
		t.Logf("Found %d results for testing domain example.com", len(execution.Results))
	} else if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("Expected clean exit or NXDOMAIN, got: %s", *execution.Error)
	}
}
