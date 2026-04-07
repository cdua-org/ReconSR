package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseRPMailbox(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard mailbox", "admin.example.com.", "admin@example.com"},
		{"dotted local part", "first.last.example.com.", "first@last.example.com"},
		{"root mailbox", ".", ""},
		{"no trailing dot", "admin.example.com", "admin@example.com"},
		{"single label", "localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRPMailbox(tt.input)
			if got != tt.expected {
				t.Errorf("parseRPMailbox(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetRPDataEmpty(t *testing.T) {
	execution := getRPData("example.com")

	if execution.Error != nil {
		t.Logf("rp lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Found RP record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetRPDataNX(t *testing.T) {
	execution := getRPData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("rp lookup failed: %v", *execution.Error)
	}
}

func TestRPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_rp") {
		t.Error("expected get_rp in capabilities")
	}
}
