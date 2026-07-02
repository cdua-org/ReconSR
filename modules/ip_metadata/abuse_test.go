package ip_metadata

import (
	"context"
	"encoding/json"
	"testing"

	"cdua-org/ReconSR/modules/utils/ripestat"
)

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

func TestGetIPAbuseContactsInvalid(t *testing.T) {
	res := getIPAbuseContacts("")
	if res.Error == nil {
		t.Error("expected error for empty IP")
	}
}

func TestGetIPAbuseContactsTimeout(t *testing.T) {
	setRIPEstatQueryMock(t, func(_ context.Context, _ string, _ string, _ any, _ int) error {
		return context.DeadlineExceeded
	})

	resAbuse := getIPAbuseContacts("198.51.100.2")
	if resAbuse.Error == nil {
		t.Error("expected timeout error for abuse contacts")
	}
}

func TestModule_LocalIDChaining_Abuse(t *testing.T) {
	mockRIPEstatSuccess(t)

	res := getIPAbuseContacts("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}

func TestGetIPAbuseContactsEmpty(t *testing.T) {
	setRIPEstatQueryMock(t, func(_ context.Context, _, _ string, result any, _ int) error {
		body := `{"data":{"abuse_contacts":["", ""]}}`
		if resp, ok := result.(*ripestat.AbuseContactResponse); ok {
			resp.RawJSON = body
		}
		return json.Unmarshal([]byte(body), result)
	})

	res := getIPAbuseContacts("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetIPAbuseContactsZero(t *testing.T) {
	setRIPEstatQueryMock(t, func(_ context.Context, _, _ string, result any, _ int) error {
		body := `{"data":{"abuse_contacts":[]}}`
		if resp, ok := result.(*ripestat.AbuseContactResponse); ok {
			resp.RawJSON = body
		}
		return json.Unmarshal([]byte(body), result)
	})

	res := getIPAbuseContacts("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}
