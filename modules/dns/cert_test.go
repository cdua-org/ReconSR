package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseCERT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format PGP",
			"\\# 10 00033039004151493d0a",
			"3 12345 0 QVFJPQo=",
		},
		{
			"passthrough cert text",
			"3 12345 0 Base64Data",
			"3 12345 0 Base64Data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCERT(tt.input)
			if got != tt.expected {
				t.Errorf("parseCERT() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetCERTDataEmpty(t *testing.T) {
	execution := getCERTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("cert lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d CERT results for example.com", len(execution.Results))
}

func TestGetCERTDataNX(t *testing.T) {
	execution := getCERTData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("cert lookup failed: %v", *execution.Error)
	}
}

func TestCERTCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetCERT) {
		t.Error("expected get_cert in capabilities")
	}
}
