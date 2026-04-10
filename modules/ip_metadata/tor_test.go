package ip_metadata

import (
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetTorDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_tor") {
		t.Error("expected get_tor in capabilities")
	}
}

func TestGetTorData(t *testing.T) {
	res := getTorData("8.8.8.8")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	}

	if len(res.Results) != 0 {
		t.Error("expected 8.8.8.8 not to be a Tor node")
	}
}

func TestGetTorDataKnown(t *testing.T) {
	resInvalid := getTorData("invalid-ip")
	if resInvalid.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}

	resKnown := getTorData("171.25.193.25")
	if resKnown.Error != nil {
		t.Logf("Network resolution error for Tor check: %v", *resKnown.Error)
	} else if len(resKnown.Results) > 0 && resKnown.Results[0].Value != "tor_exit" {
		t.Errorf("expected tor_exit value, got %s", resKnown.Results[0].Value)
	}
}

func TestGetTorDataTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	res := getTorData("8.8.8.8")
	if res.Error == nil {
		t.Error("expected network error/timeout with 1ns timeout, got nil")
	}
}

func TestGetTorDataDebug(t *testing.T) {
	t.Log("Testing debug output for Tor")
	const debugStr = "true"
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getTorData("1.1.1.1")
	getTorData("192.0.2.1")
}
