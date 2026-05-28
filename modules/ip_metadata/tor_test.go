package ip_metadata

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetTorDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetTOR) {
		t.Error("expected get_tor in capabilities")
	}
}

func TestGetTorData(t *testing.T) {
	mockAQueryResponses(t, nil, nil)

	res := getTorData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Error("expected fake IP not to be a Tor node")
	}
}

func TestGetTorDataKnown(t *testing.T) {
	resInvalid := getTorData("invalid-ip")
	if resInvalid.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}

	mockAQueryResponses(t, map[string][]string{
		".dnsel.torproject.org": {dnsblPositive},
	}, nil)

	resKnown := getTorData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}
	if len(resKnown.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resKnown.Results))
	}
	if resKnown.Results[0].Value != constants.TagTorExit {
		t.Errorf("expected %q, got %q", constants.TagTorExit, resKnown.Results[0].Value)
	}
}

func TestGetTorDataTimeout(t *testing.T) {
	mockAQueryResponses(t, nil, context.DeadlineExceeded)

	res := getTorData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_TOR(t *testing.T) {
	mockAQueryResponses(t, map[string][]string{
		".torexit.dan.me.uk": {dnsblPositive},
	}, nil)

	resKnown := getTorData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}

	requireUniqueLocalIDs(t, resKnown.Results)
}
