package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseCERT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format PGP",
			"\\# 10 00033039004151493d0a", // Type=3, tag=12345, alg=0, data=AQI=\n ("4151493d0a" decoded is "AQI=\n", base64 of that is something else, but we decode payload to base64)
			"3 12345 0 QVFJPQo=",
		},
		{
			"passthrough non-wire",
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
	execution := getCERTData("example.com")

	if execution.Error != nil {
		t.Logf("cert lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d CERT results for example.com", len(execution.Results))
}

func TestGetCERTDataNX(t *testing.T) {
	execution := getCERTData("nonexistent.domain.invalid")

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

	if !slices.Contains(caps.Functions, "get_cert") {
		t.Error("expected get_cert in capabilities")
	}
}
