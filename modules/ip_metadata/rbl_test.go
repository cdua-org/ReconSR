package ip_metadata

import (
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetRBLDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_rbl") {
		t.Error("expected get_rbl in capabilities")
	}
}

func TestGetRBLDataClean(t *testing.T) {
	res := getRBLData("8.8.8.8")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	}

	if len(res.Results) != 0 {
		t.Error("expected 8.8.8.8 not to be listed in RBLs")
	}
}

func TestGetRBLDataKnown(t *testing.T) {
	resInvalid := getRBLData("invalid-ip")
	if resInvalid.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}

	resKnown := getRBLData("127.0.0.2")
	if resKnown.Error != nil {
		t.Logf("Network resolution error for RBL check: %v", *resKnown.Error)
	} else if len(resKnown.Results) > 0 && resKnown.Results[0].Value != "spam_botnet" {
		t.Errorf("expected spam_botnet value, got %s", resKnown.Results[0].Value)
	}
}

func TestGetRBLDataTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	res := getRBLData("8.8.8.8")
	if res.Error == nil {
		t.Error("expected network error/timeout with 1ns timeout, got nil")
	}
}

func TestGetRBLDataDebug(t *testing.T) {
	t.Log("Testing debug output for RBL")
	const debugStr = "true"
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getRBLData("1.1.1.1")
	getRBLData("192.0.2.1")
}
