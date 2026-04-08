package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseHIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format",
			"\\# 18 08020004010203040506070801020304", // len 8, alg 2, pklen 4, HIT 01..08, PK 01..04
			"2 0102030405060708 AQIDBA==",             // Base64 of 01020304 is AQIDBA==
		},
		{
			"passthrough non-wire",
			"2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.com.",
			"2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.com.",
		},
		{
			"invalid hex data",
			"\\# 18 ZZ",
			"\\# 18 ZZ",
		},
		{
			"out of bounds pklen",
			"\\# 6 0802FFFF0102",
			"\\# 6 0802FFFF0102",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHIP(tt.input)
			if got != tt.expected {
				t.Errorf("parseHIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetHIPDataEmpty(t *testing.T) {
	execution := getHIPData("example.com")

	if execution.Error != nil {
		t.Logf("hip lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d HIP results for example.com", len(execution.Results))
}

func TestGetHIPDataNX(t *testing.T) {
	execution := getHIPData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("hip lookup failed: %v", *execution.Error)
	}
}

func TestHIPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_hip") {
		t.Error("expected get_hip in capabilities")
	}
}
