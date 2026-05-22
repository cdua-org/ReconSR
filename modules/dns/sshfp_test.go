package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseSSHFP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"RSA SHA-256 wire format",
			"\\# 34 01 02 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"RSA SHA-256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			"Ed25519 SHA-256 wire format",
			"\\# 34 04 02 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"Ed25519 SHA-256 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			"passthrough sshfp text",
			"1 2 abcdef0123456789",
			"1 2 abcdef0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSHFP(tt.input)
			if got != tt.expected {
				t.Errorf("parseSSHFP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetSSHFPDataEmpty(t *testing.T) {
	execution := getSSHFPData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("sshfp lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d SSHFP results for example.com", len(execution.Results))
}

func TestGetSSHFPDataNX(t *testing.T) {
	execution := getSSHFPData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("sshfp lookup failed: %v", *execution.Error)
	}
}

func TestSSHFPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSSHFP) {
		t.Error("expected get_sshfp in capabilities")
	}
}
