package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetIPSECKEYData(t *testing.T) {
	origResolve := resolveRecordFunc
	defer func() { resolveRecordFunc = origResolve }()

	tests := []struct {
		name       string
		domain     string
		mockErr    error
		mockRec    []string
		mockRaw    []byte
		wantResult int
		wantErr    bool
	}{
		{
			name:       "ipseckey_success",
			domain:     "apple.example",
			mockErr:    nil,
			mockRec:    []string{"10 1 2 192.0.2.38 AQID"},
			mockRaw:    []byte("raw"),
			wantResult: 2,
			wantErr:    false,
		},
		{
			name:       "ipseckey_resolve_error",
			domain:     "banana.example",
			mockErr:    errors.New("mock dns error"),
			mockRec:    nil,
			mockRaw:    nil,
			wantResult: 0,
			wantErr:    true,
		},
		{
			name:       "invalid_record",
			domain:     "cherry.example",
			mockErr:    nil,
			mockRec:    []string{"invalid"},
			mockRaw:    []byte("raw"),
			wantResult: 0,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return tt.mockRec, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getIPSECKEYData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getIPSECKEYData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getIPSECKEYData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
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
		{
			name:    "unknown gateway type rejected",
			gwType:  "4",
			gateway: "192.0.2.11",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classifyIPSECKEYGateway(tt.gwType, tt.gateway, "gateway.ipseckey.example.com", modutil.NewLocalIDGenerator())
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
		raw           string
		wantNodeType  string
		wantNodeValue string
		wantLen       int
		wantNodeOOS   bool
	}{
		{
			name:          "ipv4 gateway produces ip node",
			raw:           "10 1 2 192.0.2.38 AQID",
			wantLen:       1,
			wantNodeType:  constants.TypeIP,
			wantNodeValue: "192.0.2.38",
			wantNodeOOS:   false,
		},
		{
			name:          "ipv6 gateway produces ip node",
			raw:           "10 2 2 2001:db8::20 AQID",
			wantLen:       1,
			wantNodeType:  constants.TypeIP,
			wantNodeValue: "2001:db8::20",
			wantNodeOOS:   false,
		},
		{
			name:          "in scope domain gateway produces tagged subdomain node",
			raw:           "10 3 2 branch-vpn.example.com AQID",
			wantLen:       1,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "branch-vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:          "external domain gateway produces out of scope subdomain node",
			raw:           "10 3 2 branch-vpn.example.edu AQID",
			wantLen:       1,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "branch-vpn.example.edu",
			wantNodeOOS:   true,
		},
		{
			name:    "no gateway produces no nodes",
			raw:     "10 0 2 . AQID",
			wantLen: 0,
		},
		{
			name:    "unknown gateway produces no nodes",
			raw:     "10 9 2 <unknown> AQID",
			wantLen: 0,
		},
		{
			name:          "domain gateway from parsed wire format produces tagged subdomain node",
			raw:           "\\# 23 0A03020376706E076578616D706C6503636F6D00010203",
			wantLen:       1,
			wantNodeType:  constants.TypeSubdomain,
			wantNodeValue: "vpn.example.com",
			wantNodeOOS:   false,
		},
		{
			name:    "mismatched ipv4 gateway family produces no nodes",
			raw:     "10 1 2 2001:db8::1 AQID",
			wantLen: 0,
		},
		{
			name:    "invalid domain gateway produces no nodes",
			raw:     "10 3 2 vpn_example.com AQID",
			wantLen: 0,
		},
		{
			name:    "invalid parsed record produces no results",
			raw:     "broken",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := dnsutils.ParseIPSECKEY(tt.raw)
			source := &schema.EntityRef{Type: constants.TypeIPSECKEY, Value: "dummy"}
			results := buildIPSECKEYResults(parsed, "results.ipseckey.example.com", source, modutil.NewLocalIDGenerator())
			if len(results) != tt.wantLen {
				t.Fatalf("buildIPSECKEYResults() len = %d, want %d", len(results), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			node := results[0]
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
			if node.Source == nil || node.Source.Type != constants.TypeIPSECKEY {
				t.Fatalf("buildIPSECKEYResults() missing or invalid source")
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
