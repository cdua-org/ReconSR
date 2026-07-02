package ip_metadata

import (
	"context"
	"encoding/json"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/ripestat"
)

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

func TestGetIPInfoInvalid(t *testing.T) {
	res := getIPInfo("")
	if res.Error == nil {
		t.Error("expected error for empty IP")
	}
}

func TestGetIPInfoTimeout(t *testing.T) {
	setRIPEstatQueryMock(t, func(context.Context, string, string, any, int) error {
		return context.DeadlineExceeded
	})

	resInfo := getIPInfo("198.51.100.2")
	if resInfo.Error == nil {
		t.Error("expected timeout error for IP info")
	}
}

func TestModule_LocalIDChaining_Info(t *testing.T) {
	mockRIPEstatSuccess(t)

	res := getIPInfo("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}

func TestGetIPInfoZeroResults(t *testing.T) {
	setRIPEstatQueryMock(t, func(_ context.Context, _, _ string, result any, _ int) error {
		body := `{"data":{"records":[]}}`
		if resp, ok := result.(*ripestat.WhoisResponse); ok {
			resp.RawJSON = body
		}
		return json.Unmarshal([]byte(body), result)
	})

	res := getIPInfo("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetIPInfoEdgeCases(t *testing.T) {
	setRIPEstatQueryMock(t, func(_ context.Context, _, _ string, result any, _ int) error {
		body := `{"data":{"records":[[
			{"key":"unknown","value":"ignored"},
			{"key":"descr","value":"   "},
			{"key":"netname","value":"FIRST-NET"},
			{"key":"netname","value":"SECOND-NET"}
		]]}}`
		if resp, ok := result.(*ripestat.WhoisResponse); ok {
			resp.RawJSON = body
		}
		return json.Unmarshal([]byte(body), result)
	})

	res := getIPInfo("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result (first netname), got %d", len(res.Results))
	}
	if res.Results[0].Value != "FIRST-NET" {
		t.Errorf("expected FIRST-NET, got %q", res.Results[0].Value)
	}
}
