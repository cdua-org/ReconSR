package ip_metadata

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetASNDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetASN) {
		t.Error("expected get_asn in capabilities")
	}
}

func TestGetASNData(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected ASN results, got none")
	}

	foundOrigin := false
	foundPrefix := false

	for _, r := range res.Results {
		if strings.HasPrefix(r.Context, "ASN Origin") && r.Value == "AS64512" && r.Type == constants.TypeASN {
			foundOrigin = true
		}
		if r.Context == "BGP Prefix" && r.Value == "198.51.100.0/24" && r.Type == constants.TypeCIDR {
			foundPrefix = true
		}
	}

	if !foundOrigin {
		t.Error("expected at least one ASN Origin result")
	}
	if !foundPrefix {
		t.Error("expected at least one BGP Prefix result")
	}
}

func TestGetASNDataIPv6(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("2001:db8::1")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Error("expected ASN results for fake IPv6 target")
	}
}

func TestGetASNDataNoHost(t *testing.T) {
	setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
		return nil, nil
	})

	res := getASNData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for no ASN data, got: %v", *res.Error)
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
	setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
		return nil, context.DeadlineExceeded
	})

	res := getASNData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestGetASNDataDebug(t *testing.T) {
	t.Log("Testing debug output for ASN")
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer func() { resolver.Options["Debug"] = strconv.FormatBool(false) }()

	setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
		return nil, nil
	})

	getASNData("198.51.100.2")
	getASNData("192.0.2.1")
}

func TestModule_LocalIDChaining_ASN(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}
