package shodan

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIIP(t *testing.T) {
	rawBody := []byte(`{
		"asn": "AS99999",
		"domains": ["fake.example.com"],
		"hostnames": ["ptr.fake.example.com"],
		"last_update": "2027-05-05T16:15:08Z",
		"isp": "Fake ISP",
		"org": "Fake Org",
		"os": "FakeOS",
		"tags": ["faketag"],
		"data": [
			{
				"port": 443,
				"transport": "tcp",
				"timestamp": "2026-05-02T16:15:08.228066",
				"product": "FakeProduct",
				"version": "9.9",
				"hash": 2222222,
				"http": {"server": "FakeHTTP"},
				"ssl": {
					"jarm": "29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d",
					"versions": ["-TLSv1", "TLSv1.2", "TLSv1.3"],
					"cert": {
						"expires": "20270720194415Z",
						"issuer": {"O": "Example Test CA", "CN": "Example Issuer", "C": "ZZ"},
						"fingerprint": {"sha1": "00112233445566778899aabbccddeeff00112233", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
						"extensions": [
							{"name": "subjectAltName", "data": "DNS:tls.sandbox.example.com, DNS:alt.sandbox.example.com"}
						]
					}
				},
				"opts": {"heartbleed": "2026/05/02 16:15:14 198.51.100.1:443 - SAFE\n"},
				"cpe": ["cpe:/a:fake:product:9.9"],
				"cpe23": ["cpe:2.3:a:fake:product:9.9"],
				"location": {
					"city": "FakeCity",
					"country_code": "FC",
					"country_name": "Fakeland",
					"latitude": 10.1234,
					"longitude": 20.5678
				},
				"vulns": {
					"CVE-9999-9999": {
						"verified": true,
						"summary": "Fake vulnerability"
					}
				}
			}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	requireTaggedResults(t, exec.Results, testShodanTag)
	assertShodanIPServiceChain(t, exec.Results)
	assertShodanIPCoreResults(t, exec.Results)
	assertShodanIPResultTypeAbsent(t, exec.Results, resultTypeHeartbleed)
}

func assertShodanIPServiceChain(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	serviceResult := requireModuleResult(t, results, resultTypeService, testShodanService)
	if serviceResult.Category != resultCategoryProperty {
		t.Fatalf("expected service to be a property, got %q", serviceResult.Category)
	}
	if serviceResult.Source == nil || serviceResult.Source.Type != resultTypePort || serviceResult.Source.Value != "443/tcp" {
		t.Fatalf("expected service to be anchored to port 443/tcp, got %+v", serviceResult.Source)
	}

	assertShodanIPServiceSource(t, results, "hash", testShodanServiceHash)
	assertShodanIPServiceSource(t, results, resultTypeBannerTimestamp, testShodanBannerTimestamp)
	assertShodanIPServiceSource(t, results, resultTypeCertFingerprint, testShodanCertFingerprintSHA1)
	assertShodanIPServiceSource(t, results, resultTypeCertFingerprint, testShodanCertFingerprintSHA256)
	assertShodanIPServiceSource(t, results, resultTypeJARM, testShodanJARM)
	assertShodanIPServiceSource(t, results, resultTypeWebServer, "FakeHTTP")
	assertShodanIPServiceSource(t, results, resultTypeCPE, "cpe:/a:fake:product:9.9")
	assertShodanIPServiceSource(t, results, "cpe23", "cpe:2.3:a:fake:product:9.9")
	assertShodanIPServiceSource(t, results, resultTypeCVE, "CVE-9999-9999 | Verified: true | Summary: Fake vulnerability")
}

func assertShodanIPServiceSource(t *testing.T, results []schema.ModuleResult, resultType, value string) {
	t.Helper()

	result := requireModuleResult(t, results, resultType, value)
	if result.Source == nil || result.Source.Type != resultTypeService || result.Source.Value != testShodanService {
		t.Fatalf("expected %s to be chained to service, got %+v", resultType, result.Source)
	}
}

func assertShodanIPCoreResults(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	sanResult := requireModuleResult(t, results, resultTypeSANDomain, testShodanSAN)
	if sanResult.Source != nil {
		t.Fatalf("expected SAN to be attached directly to target IP, got %+v", sanResult.Source)
	}
	assertShodanIPResultSource(t, results, resultTypeCertIssuer, testShodanCertIssuer, resultTypeSANDomain, testShodanSAN)
	assertShodanIPResultSource(t, results, resultTypeCertNotAfter, testShodanCertNotAfter, resultTypeSANDomain, testShodanSAN)
	assertShodanIPResultSource(t, results, resultTypeTLSVersions, testShodanTLSVersions, resultTypeSANDomain, testShodanSAN)

	requireModuleResult(t, results, resultTypeSANDomain, testShodanAltSAN)
	requireModuleResult(t, results, "shodan_domain", "fake.example.com")
	requireModuleResult(t, results, "asn", "99999")
	requireModuleResult(t, results, "ptr", "ptr.fake.example.com")
	requireModuleResult(t, results, "isp", "Fake ISP")
	requireModuleResult(t, results, "org", "Fake Org")
	requireModuleResult(t, results, "os", "FakeOS")
	requireModuleResult(t, results, resultTypePort, "443/tcp")
	requireModuleResult(t, results, resultTypeLastUpdate, testShodanLastUpdate)

	geoResult := requireModuleResult(t, results, "geo", testShodanGeo)
	if geoResult.Category != resultCategoryProperty {
		t.Fatalf("expected geo to be a property, got %q", geoResult.Category)
	}
}

func TestParseShodanAPIIPParsesEscapedSubjectAltName(t *testing.T) {
	rawBody := []byte(`{
		"tags": ["faketag"],
		"data": [
			{
				"port": 443,
				"transport": "tcp",
				"ssl": {
					"versions": ["TLSv1.2", "TLSv1.3"],
					"cert": {
						"expires": "20270720194415Z",
						"issuer": {"O": "Example Test CA", "CN": "Example Issuer", "C": "ZZ"},
						"fingerprint": {"sha1": "00112233445566778899aabbccddeeff00112233", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
						"extensions": [
							{"name": "subjectAltName", "data": "0\\x25\\x82\\x19*.wild.sandbox.example.com\\x82\\x17wild.sandbox.example.com"}
						]
					}
				}
			}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	wildcardResult := requireModuleResult(t, exec.Results, resultTypeWildcardSANDomain, testShodanWildcardSAN)
	if wildcardResult.Source != nil {
		t.Fatalf("expected wildcard SAN to be attached directly to target IP, got %+v", wildcardResult.Source)
	}
	requireModuleResult(t, exec.Results, resultTypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, resultTypeCertFingerprint, testShodanCertFingerprintSHA1, resultTypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, resultTypeCertFingerprint, testShodanCertFingerprintSHA256, resultTypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, resultTypeCertIssuer, testShodanCertIssuer, resultTypeWildcardSANDomain, testShodanWildcardSAN)
	assertShodanIPResultSource(t, exec.Results, resultTypeCertNotAfter, testShodanCertNotAfter, resultTypeWildcardSANDomain, testShodanWildcardSAN)
	assertShodanIPResultSource(t, exec.Results, resultTypeTLSVersions, testShodanTLSVersions, resultTypeWildcardSANDomain, testShodanWildcardSAN)
	requireModuleResult(t, exec.Results, resultTypeSANDomain, "wild.sandbox.example.com")
	if _, ok := findModuleResult(exec.Results, resultTypeSANDomain, "twild.sandbox.example.com"); ok {
		t.Fatalf("expected escaped SAN data to avoid bogus tnewton.ua result, got %+v", exec.Results)
	}
}

func TestParseShodanAPIIPSkipsDuplicateWebServerValue(t *testing.T) {
	rawBody := []byte(`{
		"tags": ["faketag"],
		"data": [
			{
				"port": 443,
				"transport": "tcp",
				"product": "nginx",
				"hash": 3333333,
				"http": {"server": "nginx"},
				"cpe": ["cpe:/a:f5:nginx"],
				"cpe23": ["cpe:2.3:a:f5:nginx"],
				"_shodan": {"module": "https"}
			}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	if _, ok := findModuleResult(exec.Results, resultTypeService, "nginx"); ok {
		t.Fatalf("expected duplicate service value to be skipped, got %+v", exec.Results)
	}
	webServerResult := requireModuleResult(t, exec.Results, resultTypeWebServer, "nginx")
	if webServerResult.Source == nil || webServerResult.Source.Type != resultTypePort || webServerResult.Source.Value != "443/tcp https" {
		t.Fatalf("expected duplicate web_server value to be anchored to port 443/tcp https, got %+v", webServerResult.Source)
	}
	assertShodanIPResultSource(t, exec.Results, "hash", testShodanDuplicateHash, resultTypeWebServer, "nginx")
	assertShodanIPResultSource(t, exec.Results, resultTypeCPE, "cpe:/a:f5:nginx", resultTypeWebServer, "nginx")
	assertShodanIPResultSource(t, exec.Results, "cpe23", "cpe:2.3:a:f5:nginx", resultTypeWebServer, "nginx")
}

func assertShodanIPResultSource(t *testing.T, results []schema.ModuleResult, resultType, value, sourceType, sourceValue string) {
	t.Helper()

	result := requireModuleResult(t, results, resultType, value)
	if result.Source == nil || result.Source.Type != sourceType || result.Source.Value != sourceValue {
		t.Fatalf("expected %s to be chained to %s=%q, got %+v", resultType, sourceType, sourceValue, result.Source)
	}
}

func assertShodanIPResultTypeAbsent(t *testing.T, results []schema.ModuleResult, resultType string) {
	t.Helper()

	for _, result := range results {
		if result.Type == resultType {
			t.Fatalf("expected result type %s to be absent, got %+v", resultType, result)
		}
	}
}

func TestParseShodanAPIIPExtractsRiskyHeartbleed(t *testing.T) {
	rawBody := []byte(`{
		"tags": ["faketag"],
		"data": [
			{
				"port": 443,
				"transport": "tcp",
				"hash": 4444444,
				"opts": {"heartbleed": "2026/05/02 16:15:14 198.51.100.1:443 - VULNERABLE\n"},
				"_shodan": {"module": "https"}
			}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	requireModuleResult(t, exec.Results, resultTypePort, "443/tcp https")
	assertShodanIPResultSource(t, exec.Results, resultTypeHeartbleed, testShodanHeartbleed, resultTypePort, "443/tcp https")
}

func TestParseShodanAPIIPFallsBackToPortSource(t *testing.T) {
	rawBody := []byte(`{
		"tags": ["faketag"],
		"data": [
			{
				"port": 3478,
				"transport": "udp",
				"timestamp": "2026-05-04T18:19:25.001152",
				"hash": 1111111,
				"_shodan": {"module": "stun"}
			}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	if _, ok := findModuleResult(exec.Results, resultTypeService, testShodanFallbackSvc); ok {
		t.Fatalf("expected module label to stay on port instead of creating service node, got %+v", exec.Results)
	}
	requireModuleResult(t, exec.Results, resultTypePort, "3478/udp stun")
	assertShodanIPResultSource(t, exec.Results, "hash", testShodanRootHash, resultTypePort, "3478/udp stun")
	assertShodanIPResultSource(t, exec.Results, resultTypeBannerTimestamp, "2026-05-04T18:19:25.001152", resultTypePort, "3478/udp stun")
}

func TestGetShodanAPIIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api-info":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"query_credits":100}`)); err != nil {
				t.Errorf("write error: %v", err)
			}
		case "/shodan/host/" + testShodanAPIIPv4:
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{
				"asn": "AS99999",
				"tags": ["faketag"],
				"data": [{"port": 443, "transport": "tcp", "product": "FakeProduct", "version": "9.9", "hash": 2222222}]
			}`)); err != nil {
				t.Errorf("write error: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	originalBaseURL := shodanAPIBaseURL
	shodanAPIBaseURL = server.URL
	defer func() { shodanAPIBaseURL = originalBaseURL }()

	module := &shodanModule{apiKey: testShodanAPIKey}
	module.lastReqTime = time.Now().Add(-2 * time.Second)

	exec := module.getShodanAPIIP(schema.Entity{Type: entityTypeIP, Value: testShodanAPIIPv4})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}
	if exec.RawData == "" {
		t.Fatal("expected raw data to be preserved")
	}

	requireModuleResult(t, exec.Results, "asn", "99999")
	requireModuleResult(t, exec.Results, resultTypeService, testShodanService)
	requireModuleResult(t, exec.Results, "hash", testShodanServiceHash)
}

func TestParseShodanAPIIPInvalidJSON(t *testing.T) {
	exec := schema.ModuleExecution{Function: functionShodanAPIIP}
	parseShodanAPIIP(&exec, []byte(`{invalid json`))
	if exec.Error == nil || !strings.Contains(*exec.Error, "unmarshal json") {
		t.Fatalf("expected unmarshal error, got %+v", exec.Error)
	}
}
