package ip_metadata

import (
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestExtraCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !slices.Contains(caps.Functions, "get_ip_info") {
		t.Error("expected get_ip_info")
	}
	if !slices.Contains(caps.Functions, "get_ip_abuse_contacts") {
		t.Error("expected get_ip_abuse_contacts")
	}
}

func TestGetIPInfoClean(t *testing.T) {
	res := getIPInfo("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetIPAbuseContactsClean(t *testing.T) {
	res := getIPAbuseContacts("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetIPInfoInvalid(t *testing.T) {
	res := getIPInfo("")
	if res.Error == nil {
		t.Error("expected error for empty IP")
	}
}

func TestGetIPAbuseContactsInvalid(t *testing.T) {
	res := getIPAbuseContacts("")
	if res.Error == nil {
		t.Error("expected error for empty IP")
	}
}

func TestExtraDebug(t *testing.T) {
	t.Log("Testing debug output for Extra")
	const debugStr = "true"
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getIPInfo("8.8.8.8")
	getIPAbuseContacts("8.8.8.8")
}

func TestExtraTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	resInfo := getIPInfo("8.8.8.8")
	if resInfo.Error == nil {
		t.Error("expected network error/timeout")
	}

	resAbuse := getIPAbuseContacts("8.8.8.8")
	if resAbuse.Error == nil {
		t.Error("expected network error/timeout")
	}
}
