package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseNAPTRRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard naptr",
			"100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" _sip._udp.example.com.",
			"100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" _sip._udp.example.com.",
		},
		{
			"wire format passthrough",
			"\\# 20 0064000a0173075349502b4432550000",
			"\\# 20 0064000a0173075349502b4432550000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNAPTRRecord(tt.input)
			if got != tt.expected {
				t.Errorf("parseNAPTRRecord() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetNAPTRDataEmpty(t *testing.T) {
	execution := getNAPTRData("example.com")

	if execution.Error != nil {
		t.Logf("naptr lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d NAPTR results for example.com", len(execution.Results))
}

func TestGetNAPTRDataNX(t *testing.T) {
	execution := getNAPTRData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("naptr lookup failed: %v", *execution.Error)
	}
}

func TestNAPTRCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_naptr") {
		t.Error("expected get_naptr in capabilities")
	}
}
