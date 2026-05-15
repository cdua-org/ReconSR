package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
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
		wantType  string
		wantValue string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "ipv4 gateway stays ip",
			gwType:    "1",
			gateway:   "192.0.2.10",
			wantOK:    true,
			wantType:  constants.TypeIP,
			wantValue: "192.0.2.10",
			wantOOS:   false,
		},
		{
			name:      "ipv6 gateway stays ip",
			gwType:    "2",
			gateway:   "2001:db8::10",
			wantOK:    true,
			wantType:  constants.TypeIP,
			wantValue: "2001:db8::10",
			wantOOS:   false,
		},
		{
			name:      "domain gateway stays domain",
			gwType:    "3",
			gateway:   "example.info",
			wantOK:    true,
			wantType:  constants.TypeDomain,
			wantValue: "example.info",
			wantOOS:   true,
		},
		{
			name:      "subdomain gateway becomes tagged subdomain",
			gwType:    "3",
			gateway:   "vpn-gateway.example.com",
			wantOK:    true,
			wantType:  constants.TypeSubdomain,
			wantValue: "vpn-gateway.example.com",
			wantOOS:   false,
		},
		{
			name:      "external subdomain gateway stays out of scope",
			gwType:    "3",
			gateway:   "vpn-gateway.example.edu",
			wantOK:    true,
			wantType:  constants.TypeSubdomain,
			wantValue: "vpn-gateway.example.edu",
			wantOOS:   true,
		},
		{
			name:    "ipv4 gateway rejects ipv6 value",
			gwType:  "1",
			gateway: "2001:db8::11",
			wantOK:  false,
		},
		{
			name:    "domain gateway rejects invalid domain",
			gwType:  "3",
			gateway: "vpn_example.com",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classifyIPSECKEYGateway(tt.gwType, tt.gateway, "gateway.ipseckey.example.com")
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
			if !slices.Contains(got.Tags, constants.TagIPSECKEY) {
				t.Fatalf("classifyIPSECKEYGateway() missing tag %q", constants.TagIPSECKEY)
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
		wantNodeType  string
		wantNodeValue string
		wantLen       int
		wantNodeOOS   bool
	}{
		{
			name:          "ipv4 gateway produces ip node",
			parsed:        "10 1 2 192.0.2.38 AQID",
			wantLen:       2,
			wantNodeType:  constants.TypeIP,
			wantNodeValue: "192.0.2.38",
			wantNodeOOS:   false,
		},
		{
			name:          "ipv6 gateway produces ip node",
			parsed:        "10 2 2 2001:db8::20 AQID",
			wantLen:       2,
			wantNodeType:  constants.TypeIP,
			wantNodeValue: "2001:db8::20",
			wantNodeOOS:   false,
		},
		{
			name:          "in scope domain gateway produces tagged subdomain node",
			parsed:        "10 3 2 branch-vpn.example.com AQID",
			wantLen:       2,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "branch-vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:          "external domain gateway produces out of scope subdomain node",
			parsed:        "10 3 2 branch-vpn.example.edu AQID",
			wantLen:       2,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "branch-vpn.example.edu",
			wantNodeOOS:   true,
		},
		{
			name:    "no gateway produces property only",
			parsed:  "10 0 2 . AQID",
			wantLen: 1,
		},
		{
			name:    "unknown gateway produces property only",
			parsed:  "10 9 2 <unknown> AQID",
			wantLen: 1,
		},
		{
			name:          "domain gateway from parsed wire format produces tagged subdomain node",
			parsed:        parseIPSECKEY("\\# 23 0A03020376706E076578616D706C6503636F6D00010203"),
			wantLen:       2,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:    "mismatched ipv4 gateway family produces property only",
			parsed:  "10 1 2 2001:db8::1 AQID",
			wantLen: 1,
		},
		{
			name:    "invalid domain gateway produces property only",
			parsed:  "10 3 2 vpn_example.com AQID",
			wantLen: 1,
		},
		{
			name:    "invalid parsed record produces no results",
			parsed:  "broken",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := buildIPSECKEYResults(tt.parsed, "results.ipseckey.example.com")
			if len(results) != tt.wantLen {
				t.Fatalf("buildIPSECKEYResults() len = %d, want %d", len(results), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			if results[0].Type != constants.TypeIPSECKEY {
				t.Fatalf("buildIPSECKEYResults() property type = %q, want %q", results[0].Type, constants.TypeIPSECKEY)
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
			if !slices.Contains(node.Tags, constants.TagIPSECKEY) {
				t.Fatalf("buildIPSECKEYResults() node missing tag %q", constants.TagIPSECKEY)
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

	if !slices.Contains(caps.Functions, constants.FuncGetIPSECKEY) {
		t.Error("expected get_ipseckey in capabilities")
	}
}
