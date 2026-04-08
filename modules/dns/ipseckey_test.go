package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseIPSECKEY(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format no gateway",
			"\\# 6 0A0002010203", // 10, 0, 2, PK=010203 -> AQID
			"10 0 2 . AQID",
		},
		{
			"standard wire format ipv4 gateway",
			"\\# 10 0A0102C0000226010203", // 10, 1, 2, GW=192.0.2.38, PK=010203
			"10 1 2 192.0.2.38 AQID",
		},
		{
			"passthrough non-wire",
			"10 1 2 192.0.2.38 AQO",
			"10 1 2 192.0.2.38 AQO",
		},
		{
			"standard wire format ipv6 gateway",
			"\\# 22 0A020220010DB8000000000000000000000001010203", // 10, 2, 2, GW is 2001:db8::1, PK is 010203
			"10 2 2 2001:db8::1 AQID",
		},
		{
			"standard wire format domain gateway",
			"\\# 10 0A03020376706E00010203", // 10, 3, 2, GW is vpn. (wire 03 76 70 6E 00), PK is 010203
			"10 3 2 <wire_domain> AQID",
		},
		{
			"out of bounds ipv4",
			"\\# 5 0A01020102",
			"\\# 5 0A01020102",
		},
		{
			"unknown gateway type",
			"\\# 6 0A0902010203", // 10, 9, 2, PK is 010203
			"10 9 2 <unknown> AQID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPSECKEY(tt.input)
			if got != tt.expected {
				t.Errorf("parseIPSECKEY() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetIPSECKEYDataEmpty(t *testing.T) {
	execution := getIPSECKEYData("example.com")

	if execution.Error != nil {
		t.Logf("ipseckey lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d IPSECKEY results for example.com", len(execution.Results))
}

func TestGetIPSECKEYDataNX(t *testing.T) {
	execution := getIPSECKEYData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("ipseckey lookup failed: %v", *execution.Error)
	}
}

func TestIPSECKEYCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_ipseckey") {
		t.Error("expected get_ipseckey in capabilities")
	}
}
