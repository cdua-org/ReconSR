package ip_metadata

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestExtraCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !slices.Contains(caps.Functions, constants.FuncGetIPInfo) {
		t.Error("expected get_ip_info")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetIPAbuseContacts) {
		t.Error("expected get_ip_abuse_contacts")
	}
}

func TestGetIPInfoClean(t *testing.T) {
	mockRIPEstatSuccess(t)

	res := getIPInfo("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res.Results))
	}

	foundNetName := false
	foundDescription := false
	for _, result := range res.Results {
		if result.Type == constants.TypeNetName && result.Value == "EXAMPLE-NET" {
			foundNetName = true
		}
		if result.Type == constants.TypeDescription && result.Value == "Example network description" {
			foundDescription = true
		}
	}

	if !foundNetName {
		t.Error("expected netname result")
	}
	if !foundDescription {
		t.Error("expected description result")
	}
}

func TestGetIPAbuseContactsClean(t *testing.T) {
	mockRIPEstatSuccess(t)

	res := getIPAbuseContacts("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.Results[0].Value != "abuse@example.com" {
		t.Errorf("expected %q, got %q", "abuse@example.com", res.Results[0].Value)
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
	resolver.Options["Debug"] = strconv.FormatBool(true)
	defer func() { resolver.Options["Debug"] = strconv.FormatBool(false) }()

	mockRIPEstatSuccess(t)

	getIPInfo("198.51.100.2")
	getIPAbuseContacts("198.51.100.2")
}

func TestExtraTimeout(t *testing.T) {
	setRIPEstatQueryMock(t, func(context.Context, string, string, any, int) error {
		return context.DeadlineExceeded
	})

	resInfo := getIPInfo("198.51.100.2")
	if resInfo.Error == nil {
		t.Error("expected timeout error for IP info")
	}

	resAbuse := getIPAbuseContacts("198.51.100.2")
	if resAbuse.Error == nil {
		t.Error("expected timeout error for abuse contacts")
	}
}
