package asn_metadata

import (
	"context"
	"encoding/json"
	"testing"

	"cdua-org/ReconSR/modules/utils/ripestat"
)

func setRIPEstatQueryMock(t *testing.T, fn func(ctx context.Context, resource, endpoint string, result any, maxRetries int) error) {
	t.Helper()
	old := ripestatQueryFunc
	ripestatQueryFunc = fn
	t.Cleanup(func() {
		ripestatQueryFunc = old
	})
}

func mockRIPEstatSuccess(t *testing.T) {
	t.Helper()
	setRIPEstatQueryMock(t, func(_ context.Context, _, endpoint string, result any, _ int) error {
		var body string
		switch endpoint {
		case "asn-neighbours":
			body = `{"data":{"neighbours":[{"asn":64519,"type":"right","v4_peers":10}]}}`
			if resp, ok := result.(*ripestat.APIResponse); ok {
				resp.RawJSON = body
			}
		case "announced-prefixes":
			body = `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`
			if resp, ok := result.(*ripestat.AnnouncedPrefixesResponse); ok {
				resp.RawJSON = body
			}
		case "as-overview":
			body = `{"data":{"holder":"-Private Use AS-"}}`
			if resp, ok := result.(*ripestat.ASOverviewResponse); ok {
				resp.RawJSON = body
			}
		case "abuse-contact-finder":
			body = `{"data":{"abuse_contacts":["abuse@example.com"]}}`
			if resp, ok := result.(*ripestat.AbuseContactResponse); ok {
				resp.RawJSON = body
			}
		default:
			return nil
		}
		return json.Unmarshal([]byte(body), result)
	})
}
