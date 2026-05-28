package ip_metadata

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetRBLDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetRBL) {
		t.Error("expected get_rbl in capabilities")
	}
}

func TestGetRBLDataClean(t *testing.T) {
	mockAQueryResponses(t, nil, nil)

	res := getRBLData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Error("expected fake IP not to be listed in RBLs")
	}
}

func TestGetRBLDataKnown(t *testing.T) {
	resInvalid := getRBLData("invalid-ip")
	if resInvalid.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}

	mockAQueryResponses(t, map[string][]string{
		".zen.spamhaus.org": {"127.0.0.3"},
	}, nil)

	resKnown := getRBLData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}
	if len(resKnown.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resKnown.Results))
	}
	if resKnown.Results[0].Value != constants.TagSpamBotnet {
		t.Errorf("expected %q, got %q", constants.TagSpamBotnet, resKnown.Results[0].Value)
	}
}

func TestGetRBLDataTimeout(t *testing.T) {
	mockAQueryResponses(t, nil, context.DeadlineExceeded)

	res := getRBLData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_RBL(t *testing.T) {
	mockAQueryResponses(t, map[string][]string{
		".b.barracudacentral.org": {"127.0.0.3"},
	}, nil)

	resKnown := getRBLData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}

	requireUniqueLocalIDs(t, resKnown.Results)
}
