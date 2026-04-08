package dns

import (
	"slices"
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

func TestGetOPENPGPKEYDataEmpty(t *testing.T) {
	execution := getOPENPGPKEYData("example.com")

	if execution.Error != nil {
		t.Logf("openpgpkey lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d OPENPGPKEY results for example.com", len(execution.Results))
}

func TestGetOPENPGPKEYDataNX(t *testing.T) {
	execution := getOPENPGPKEYData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("openpgpkey lookup failed: %v", *execution.Error)
	}
}

func TestOPENPGPKEYCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_openpgpkey") {
		t.Error("expected get_openpgpkey in capabilities")
	}
}
