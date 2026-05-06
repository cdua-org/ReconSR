package shodan

import (
	"testing"

	"cdua-org/ReconSR/schema"
)

const (
	testShodanAPIIPv4               = "198.51.100.1"
	testShodanAPIDomain             = "example.com"
	testShodanAPIKey                = "test-key"
	testShodanTag                   = "faketag"
	testShodanService               = "FakeProduct 9.9"
	testShodanSAN                   = "tls.sandbox.example.com"
	testShodanAltSAN                = "alt.sandbox.example.com"
	testShodanWildcardSAN           = "*.wild.sandbox.example.com"
	testShodanCertFingerprintSHA1   = "sha1:00112233445566778899aabbccddeeff00112233"
	testShodanCertFingerprintSHA256 = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testShodanCertIssuer            = "O: Example Test CA | CN: Example Issuer | C: ZZ"
	testShodanCertNotAfter          = "2027-07-20T19:44:15Z"
	testShodanTLSVersions           = "TLSv1.2, TLSv1.3"
	testShodanJARM                  = "29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d"
	testShodanLastUpdate            = "2027-05-05T16:15:08Z"
	testShodanBannerTimestamp       = "2026-05-02T16:15:08.228066"
	testShodanGeo                   = "City: FakeCity | Country: Fakeland (FC) | Lat/Lon: 10.123400, 20.567800"
	testShodanHeartbleed            = "VULNERABLE"
	testShodanRootHash              = "1111111"
	testShodanServiceHash           = "2222222"
	testShodanDuplicateHash         = "3333333"
	testShodanFallbackSvc           = "stun"
)

func findModuleResult(results []schema.ModuleResult, resultType, value string) (schema.ModuleResult, bool) {
	for _, result := range results {
		if result.Type == resultType && result.Value == value {
			return result, true
		}
	}

	return schema.ModuleResult{}, false
}

func requireModuleResult(t *testing.T, results []schema.ModuleResult, resultType, value string) schema.ModuleResult {
	t.Helper()

	result, ok := findModuleResult(results, resultType, value)
	if !ok {
		t.Fatalf("expected result %s=%q, got %+v", resultType, value, results)
	}

	return result
}

func requireTaggedResults(t *testing.T, results []schema.ModuleResult, expectedTag string) {
	t.Helper()

	for _, result := range results {
		if len(result.Tags) != 1 || result.Tags[0] != expectedTag {
			t.Fatalf("expected tag %q, got %+v", expectedTag, result.Tags)
		}
	}
}

func requireModuleResultWithContext(t *testing.T, results []schema.ModuleResult, resultType, value, context string) schema.ModuleResult {
	t.Helper()

	for _, result := range results {
		if result.Type == resultType && result.Value == value && result.Context == context {
			return result
		}
	}

	t.Fatalf("expected result %s=%q context=%q not found", resultType, value, context)
	return schema.ModuleResult{}
}

func findModuleResultBySource(results []schema.ModuleResult, resultType, sourceType, sourceValue string) *schema.ModuleResult {
	for i, result := range results {
		if result.Type != resultType {
			continue
		}

		if sourceType == "" && sourceValue == "" {
			if result.Source == nil {
				return &results[i]
			}

			continue
		}

		if result.Source != nil && result.Source.Type == sourceType && result.Source.Value == sourceValue {
			return &results[i]
		}
	}

	return nil
}
