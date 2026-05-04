package dns

import (
	"context"
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
			"\\# 6 0A0002010203",
			"10 0 2 . AQID",
		},
		{
			"standard wire format ipv4 gateway",
			"\\# 10 0A0102C0000226010203",
			"10 1 2 192.0.2.38 AQID",
		},
		{
			"passthrough non-wire",
			"10 1 2 192.0.2.38 AQO",
			"10 1 2 192.0.2.38 AQO",
		},
		{
			"standard wire format ipv6 gateway",
			"\\# 22 0A020220010DB8000000000000000000000001010203",
			"10 2 2 2001:db8::1 AQID",
		},
		{
			"standard wire format domain gateway",
			"\\# 23 0A03020376706E076578616D706C6503636F6D00010203",
			"10 3 2 vpn.example.com AQID",
		},
		{
			"out of bounds ipv4",
			"\\# 5 0A01020102",
			"\\# 5 0A01020102",
		},
		{
			"unknown gateway type",
			"\\# 6 0A0902010203",
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
	execution := getIPSECKEYData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("ipseckey lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d IPSECKEY results for example.com", len(execution.Results))
}

func TestGetIPSECKEYDataNX(t *testing.T) {
	execution := getIPSECKEYData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("ipseckey lookup failed: %v", *execution.Error)
	}
}

func TestClassifyIPSECKEYGateway(t *testing.T) {
	tests := []struct {
		name      string
		gwType    string
		gateway   string
		target    string
		wantType  string
		wantValue string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "ipv4 gateway stays ip",
			gwType:    "1",
			gateway:   "192.0.2.10",
			target:    "example.com",
			wantOK:    true,
			wantType:  "ip",
			wantValue: "192.0.2.10",
			wantOOS:   false,
		},
		{
			name:      "ipv6 gateway stays ip",
			gwType:    "2",
			gateway:   "2001:db8::1",
			target:    "example.com",
			wantOK:    true,
			wantType:  "ip",
			wantValue: "2001:db8::1",
			wantOOS:   false,
		},
		{
			name:      "domain gateway becomes ipsec gateway",
			gwType:    "3",
			gateway:   "vpn.example.com",
			target:    "example.com",
			wantOK:    true,
			wantType:  ipsecGatewayType,
			wantValue: "vpn.example.com",
			wantOOS:   false,
		},
		{
			name:      "external domain gateway stays out of scope",
			gwType:    "3",
			gateway:   "vpn.vendor.net",
			target:    "example.com",
			wantOK:    true,
			wantType:  ipsecGatewayType,
			wantValue: "vpn.vendor.net",
			wantOOS:   true,
		},
		{
			name:    "ipv4 gateway rejects ipv6 value",
			gwType:  "1",
			gateway: "2001:db8::1",
			target:  "example.com",
			wantOK:  false,
		},
		{
			name:    "domain gateway rejects invalid domain",
			gwType:  "3",
			gateway: "vpn_example.com",
			target:  "example.com",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classifyIPSECKEYGateway(tt.gwType, tt.gateway, tt.target)
			if ok != tt.wantOK {
				t.Fatalf("classifyIPSECKEYGateway() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.Type != tt.wantType {
				t.Fatalf("classifyIPSECKEYGateway() type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Value != tt.wantValue {
				t.Fatalf("classifyIPSECKEYGateway() value = %q, want %q", got.Value, tt.wantValue)
			}
			if got.OutOfScope != tt.wantOOS {
				t.Fatalf("classifyIPSECKEYGateway() out_of_scope = %v, want %v", got.OutOfScope, tt.wantOOS)
			}
		})
	}
}

func TestBuildIPSECKEYResults(t *testing.T) {
	tests := []struct {
		name          string
		parsed        string
		target        string
		wantNodeType  string
		wantNodeValue string
		wantLen       int
		wantNodeOOS   bool
	}{
		{
			name:          "ipv4 gateway produces ip node",
			parsed:        "10 1 2 192.0.2.38 AQID",
			target:        "example.com",
			wantLen:       2,
			wantNodeType:  "ip",
			wantNodeValue: "192.0.2.38",
			wantNodeOOS:   false,
		},
		{
			name:          "ipv6 gateway produces ip node",
			parsed:        "10 2 2 2001:db8::1 AQID",
			target:        "example.com",
			wantLen:       2,
			wantNodeType:  "ip",
			wantNodeValue: "2001:db8::1",
			wantNodeOOS:   false,
		},
		{
			name:          "in scope domain gateway produces ipsec gateway node",
			parsed:        "10 3 2 vpn.example.com AQID",
			target:        "example.com",
			wantLen:       2,
			wantNodeType:  ipsecGatewayType,
			wantNodeValue: "vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:          "external domain gateway produces out of scope ipsec gateway node",
			parsed:        "10 3 2 vpn.vendor.net AQID",
			target:        "example.com",
			wantLen:       2,
			wantNodeType:  ipsecGatewayType,
			wantNodeValue: "vpn.vendor.net",
			wantNodeOOS:   true,
		},
		{
			name:    "no gateway produces property only",
			parsed:  "10 0 2 . AQID",
			target:  "example.com",
			wantLen: 1,
		},
		{
			name:    "unknown gateway produces property only",
			parsed:  "10 9 2 <unknown> AQID",
			target:  "example.com",
			wantLen: 1,
		},
		{
			name:          "domain gateway from parsed wire format produces ipsec gateway node",
			parsed:        parseIPSECKEY("\\# 23 0A03020376706E076578616D706C6503636F6D00010203"),
			target:        "example.com",
			wantLen:       2,
			wantNodeType:  ipsecGatewayType,
			wantNodeValue: "vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:    "mismatched ipv4 gateway family produces property only",
			parsed:  "10 1 2 2001:db8::1 AQID",
			target:  "example.com",
			wantLen: 1,
		},
		{
			name:    "invalid domain gateway produces property only",
			parsed:  "10 3 2 vpn_example.com AQID",
			target:  "example.com",
			wantLen: 1,
		},
		{
			name:    "invalid parsed record produces no results",
			parsed:  "broken",
			target:  "example.com",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := buildIPSECKEYResults(tt.parsed, tt.target)
			if len(results) != tt.wantLen {
				t.Fatalf("buildIPSECKEYResults() len = %d, want %d", len(results), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			if results[0].Type != "ipseckey" {
				t.Fatalf("buildIPSECKEYResults() property type = %q, want %q", results[0].Type, "ipseckey")
			}
			if tt.wantLen == 1 {
				return
			}
			node := results[1]
			if node.Type != tt.wantNodeType {
				t.Fatalf("buildIPSECKEYResults() node type = %q, want %q", node.Type, tt.wantNodeType)
			}
			if node.Value != tt.wantNodeValue {
				t.Fatalf("buildIPSECKEYResults() node value = %q, want %q", node.Value, tt.wantNodeValue)
			}
			if node.OutOfScope != tt.wantNodeOOS {
				t.Fatalf("buildIPSECKEYResults() node out_of_scope = %v, want %v", node.OutOfScope, tt.wantNodeOOS)
			}
		})
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
