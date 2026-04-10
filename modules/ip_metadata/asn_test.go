package ip_metadata

import (
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetASNDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_asn") {
		t.Error("expected get_asn in capabilities")
	}
}

func TestGetASNData(t *testing.T) {
	res := getASNData("8.8.8.8")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected ASN results for 8.8.8.8")
	}

	foundOrigin := false
	foundPrefix := false

	for _, r := range res.Results {
		if strings.HasPrefix(r.Context, "ASN Origin") {
			foundOrigin = true
		}
		if r.Context == "BGP Prefix" {
			foundPrefix = true
		}
	}

	if !foundOrigin {
		t.Error("expected at least one ASN Origin")
	}
	if !foundPrefix {
		t.Error("expected at least one BGP Prefix")
	}
}

func TestGetASNDataIPv6(t *testing.T) {
	res := getASNData("2001:4860:4860::8888")

	if res.Error != nil {
		t.Logf("Network resolution error for IPv6: %v", *res.Error)
		return
	}

	if len(res.Results) == 0 {
		t.Error("expected ASN results for 2001:4860:4860::8888")
	}
}

func TestGetASNDataNoHost(t *testing.T) {
	// Reserved TEST-NET-1 space shouldn't have BGP announcements
	res := getASNData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for non-existent ASN, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetASNDataInvalidIP(t *testing.T) {
	res := getASNData("invalid-ip")
	if res.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestGetASNDataTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	res := getASNData("8.8.8.8")
	if res.Error == nil {
		t.Error("expected network error/timeout with 1ns timeout, got nil")
	}
}

func TestGetASNDataDebug(t *testing.T) {
	t.Log("Testing debug output for ASN")
	const debugStr = "true"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = "false" }()

	getASNData("1.1.1.1")
	getASNData("192.0.2.1")
}

func TestReverseIPForCymru(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
		isIPv4   bool
		isErr    bool
	}{
		{"8.8.8.8", "8.8.8.8", true, false},
		{"93.184.216.34", "34.216.184.93", true, false},
		{"2001:4860:4860::8888", "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2", false, false},
		{"invalid", "", false, true},
	}

	for _, tt := range tests {
		rev, isIPv4, err := reverseIPForCymru(tt.ip)
		if (err != nil) != tt.isErr {
			t.Errorf("ip %q: expected error %v, got %v", tt.ip, tt.isErr, err)
		}
		if rev != tt.expected {
			t.Errorf("ip %q: expected %q, got %q", tt.ip, tt.expected, rev)
		}
		if isIPv4 != tt.isIPv4 {
			t.Errorf("ip %q: expected isIPv4 %v, got %v", tt.ip, tt.isIPv4, isIPv4)
		}
	}
}
