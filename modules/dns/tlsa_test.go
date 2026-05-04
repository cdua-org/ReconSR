package dns

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestParseTLSA(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format",
			"\\# 35 03 01 01 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"3 1 1 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			"passthrough non-wire",
			"3 1 1 abcdef0123456789",
			"3 1 1 abcdef0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTLSA(tt.input)
			if got != tt.expected {
				t.Errorf("parseTLSA() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetTLSADataEmpty(t *testing.T) {
	execution := getTLSAData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("tlsa lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d TLSA results for example.com", len(execution.Results))
}

func TestGetTLSADataNX(t *testing.T) {
	execution := getTLSAData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("tlsa lookup failed: %v", *execution.Error)
	}
}

func TestTLSACapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_tlsa") {
		t.Error("expected get_tlsa in capabilities")
	}
}
