package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestParseDS(t *testing.T) {
	const parsedDSRecord = "3437 8 2 1234567890ABCDEF1234567890ABCDEF"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard ds wire format",
			"\\# 20 0d6d08021234567890abcdef1234567890abcdef",
			parsedDSRecord,
		},
		{
			"passthrough ds text",
			parsedDSRecord,
			parsedDSRecord,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDS(tt.input)
			if got != tt.expected {
				t.Errorf("parseDS() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetDSDataEmpty(t *testing.T) {
	execution := getDSData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("ds lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d DS results for example.com", len(execution.Results))
}

func TestGetDSDataNX(t *testing.T) {
	execution := getDSData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("ds lookup failed: %v", *execution.Error)
	}
}

func TestDSCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDS) {
		t.Error("expected get_ds in capabilities")
	}
}
