package ip_metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func setTXTQueryMock(t *testing.T, fn func(target, query, queryType string) ([]string, error)) {
	t.Helper()
	old := txtQueryFunc
	txtQueryFunc = fn
	t.Cleanup(func() {
		txtQueryFunc = old
	})
}

func setPTRQueryMock(t *testing.T, fn func(target string) ([]string, error)) {
	t.Helper()
	old := ptrQueryFunc
	ptrQueryFunc = fn
	t.Cleanup(func() {
		ptrQueryFunc = old
	})
}

func setAQueryMock(t *testing.T, fn func(target, query, queryType string) ([]string, error)) {
	t.Helper()
	old := aQueryFunc
	aQueryFunc = fn
	t.Cleanup(func() {
		aQueryFunc = old
	})
}

func setRIPEstatQueryMock(t *testing.T, fn func(ctx context.Context, resource, endpoint string, result any, maxRetries int) error) {
	t.Helper()
	old := ripestatQueryFunc
	ripestatQueryFunc = fn
	t.Cleanup(func() {
		ripestatQueryFunc = old
	})
}

func mockASNLookup(t *testing.T) {
	t.Helper()
	setTXTQueryMock(t, func(_, _, queryType string) ([]string, error) {
		switch queryType {
		case "origin":
			return []string{"64512 | 198.51.100.0/24"}, nil
		case "asn_info":
			return []string{"ignored | ZZ | ignored | ignored | Example Network Operations LLC"}, nil
		default:
			return nil, nil
		}
	})
}

func mockAQueryResponses(t *testing.T, responses map[string][]string, err error) {
	t.Helper()
	setAQueryMock(t, func(_, query, _ string) ([]string, error) {
		if err != nil {
			return nil, err
		}
		for suffix, result := range responses {
			if strings.Contains(query, suffix) {
				return result, nil
			}
		}
		return nil, nil
	})
}

func mockRIPEstatSuccess(t *testing.T) {
	t.Helper()
	setRIPEstatQueryMock(t, func(_ context.Context, _, endpoint string, result any, _ int) error {
		var body string
		switch endpoint {
		case "whois":
			body = fmt.Sprintf(`{"data":{"records":[[{"key":"netname","value":%q},{"key":"descr","value":%q}]]}}`, "EXAMPLE-NET", "Example network description")
			if resp, ok := result.(*ripestat.WhoisResponse); ok {
				resp.RawJSON = body
			}
		case "abuse-contact-finder":
			body = fmt.Sprintf(`{"data":{"abuse_contacts":[%q]}}`, "abuse@example.com")
			if resp, ok := result.(*ripestat.AbuseContactResponse); ok {
				resp.RawJSON = body
			}
		default:
			return nil
		}
		return json.Unmarshal([]byte(body), result)
	})
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}
