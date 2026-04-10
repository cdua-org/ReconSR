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
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getASNData("1.1.1.1")
	getASNData("192.0.2.1")
}
