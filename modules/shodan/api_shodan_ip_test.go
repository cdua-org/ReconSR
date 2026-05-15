package shodan

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIIP(t *testing.T) {
	targetIP := shodanTestAPIIPv4()
	service := "FakeProduct 9.9"
	rawBody := loadShodanFixture(t, "ip_full.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody, targetIP)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	requireTagPropertyResults(t, exec.Results, "faketag")
	assertShodanIPServiceChain(t, exec.Results, targetIP, service)
	assertShodanIPCoreResults(t, exec.Results)
	assertShodanIPResultTypeAbsent(t, exec.Results, constants.TypeHeartbleed)
}

func assertShodanIPServiceChain(t *testing.T, results []schema.ModuleResult, targetIP, service string) {
	t.Helper()

	serviceResult := requireModuleResult(t, results, constants.TypeService, service)
	if serviceResult.Category != constants.CategoryProperty {
		t.Fatalf("expected service to be a property, got %q", serviceResult.Category)
	}
	if serviceResult.Source != nil {
		t.Fatalf("expected service to be anchored directly to IP, got %+v", serviceResult.Source)
	}

	assertShodanIPResultSource(t, results, constants.TypeWebServer, "FakeHTTP", constants.TypeService, service)

	portResult := requireModuleResult(t, results, constants.TypePort, "443/tcp")
	if portResult.Source == nil || portResult.Source.Type != constants.TypeService || portResult.Source.Value != service {
		t.Fatalf("expected port to be chained to service, got %+v", portResult.Source)
	}

	assertShodanIPPortSource(t, results, constants.TypeHash, "2222222")
	assertShodanIPPortSource(t, results, constants.TypeBannerTimestamp, "2026-05-02T16:15:08.228066")
	assertShodanIPPortSource(t, results, constants.TypeCertFingerprint, "sha1:00112233445566778899aabbccddeeff00112233")
	assertShodanIPPortSource(t, results, constants.TypeCertFingerprint, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	assertShodanIPPortSource(t, results, constants.TypeJARM, "29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d29d")
	assertShodanIPPortSource(t, results, constants.TypeCPE, "cpe:/a:fake:product:9.9")
	assertShodanIPPortSource(t, results, constants.TypeCPE23, "cpe:2.3:a:fake:product:9.9")

	assertShodanIPCVEChain(t, results, targetIP, service)
}

func assertShodanIPCVEChain(t *testing.T, results []schema.ModuleResult, targetIP, service string) {
	t.Helper()

	vulnCtx := targetIP + ":443/tcp (" + service + ")"

	assertCVEWithSummary(t, results, service, vulnCtx)
	assertCVEWithCVSS(t, results, vulnCtx)
	assertCVEWithEPSS(t, results, vulnCtx)
}

func assertCVEWithSummary(t *testing.T, results []schema.ModuleResult, service, vulnCtx string) {
	t.Helper()

	cve := requireModuleResult(t, results, constants.TypeCVE, "CVE-1111-1001")
	if cve.Category != constants.CategoryNode {
		t.Fatalf("expected cve to be a node, got %q", cve.Category)
	}
	if cve.Source == nil || cve.Source.Type != constants.TypeService || cve.Source.Value != service {
		t.Fatalf("expected cve to be chained to service, got %+v", cve.Source)
	}

	verified := requireModuleResultWithContext(t, results, constants.TypeVerified, "true", vulnCtx)
	if verified.Source == nil || verified.Source.Value != "CVE-1111-1001" {
		t.Fatalf("expected verified to be chained to cve, got %+v", verified.Source)
	}

	summary := requireModuleResultWithContext(t, results, constants.TypeSummary, "Fake vulnerability alpha", vulnCtx)
	if summary.Source == nil || summary.Source.Value != "CVE-1111-1001" {
		t.Fatalf("expected summary to be chained to cve, got %+v", summary.Source)
	}
}

func assertCVEWithCVSS(t *testing.T, results []schema.ModuleResult, vulnCtx string) {
	t.Helper()

	requireModuleResult(t, results, constants.TypeCVE, "CVE-2222-2002")

	cvss := requireModuleResultWithContext(t, results, constants.TypeCVSS, "9.8 (v3.0)", vulnCtx)
	if cvss.Source == nil || cvss.Source.Value != "CVE-2222-2002" {
		t.Fatalf("expected cvss to be chained to cve, got %+v", cvss.Source)
	}
}

func assertCVEWithEPSS(t *testing.T, results []schema.ModuleResult, vulnCtx string) {
	t.Helper()

	requireModuleResult(t, results, constants.TypeCVE, "CVE-3333-3003")

	epss := requireModuleResultWithContext(t, results, constants.TypeEPSS, "0.03%", vulnCtx)
	if epss.Source == nil || epss.Source.Value != "CVE-3333-3003" {
		t.Fatalf("expected epss to be chained to cve, got %+v", epss.Source)
	}

	rank := requireModuleResultWithContext(t, results, constants.TypeRankEPSS, "7.15%", vulnCtx)
	if rank.Source == nil || rank.Source.Value != "CVE-3333-3003" {
		t.Fatalf("expected ranking_epss to be chained to cve, got %+v", rank.Source)
	}
}

func assertShodanIPPortSource(t *testing.T, results []schema.ModuleResult, resultType, value string) {
	t.Helper()

	result := requireModuleResult(t, results, resultType, value)
	if result.Source == nil || result.Source.Type != constants.TypePort || result.Source.Value != "443/tcp" {
		t.Fatalf("expected %s to be chained to port, got %+v", resultType, result.Source)
	}
}

func assertShodanIPCoreResults(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	sanResult := requireModuleResult(t, results, constants.TypeSANDomain, "tls.sandbox.example.com")
	if sanResult.Source != nil {
		t.Fatalf("expected SAN to be attached directly to target IP, got %+v", sanResult.Source)
	}
	assertShodanIPResultSource(t, results, constants.TypeCertIssuer, "O: Example Test CA | CN: Example Issuer | C: ZZ", constants.TypeSANDomain, "tls.sandbox.example.com")
	assertShodanIPResultSource(t, results, constants.TypeCertNotAfter, "2027-07-20T19:44:15Z", constants.TypeSANDomain, "tls.sandbox.example.com")
	assertShodanIPResultSource(t, results, constants.TypeTLSVersions, "TLSv1.2, TLSv1.3", constants.TypeSANDomain, "tls.sandbox.example.com")

	requireModuleResult(t, results, constants.TypeSANDomain, "alt.sandbox.example.com")
	shodanDomain := requireModuleResult(t, results, constants.TypeSubdomain, "fake.example.com")
	if !slices.Contains(shodanDomain.Tags, constants.TagReverseIP) {
		t.Fatalf("expected shodan domain to have tag %q, got tags %v", constants.TagReverseIP, shodanDomain.Tags)
	}
	requireModuleResult(t, results, constants.TypeASN, "99999")
	ptrDomain := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "ptr.fake.example.com", "Shodan PTR")
	if !slices.Contains(ptrDomain.Tags, constants.TagReverseIP) {
		t.Fatalf("expected validated PTR domain to have tag %q, got tags %v", constants.TagReverseIP, ptrDomain.Tags)
	}
	requireModuleResult(t, results, constants.TypeISP, "Fake ISP")
	requireModuleResult(t, results, constants.TypeOrg, "Fake Org")
	requireModuleResult(t, results, constants.TypeOS, "FakeOS")
	requireModuleResult(t, results, constants.TypePort, "443/tcp")
	requireModuleResult(t, results, constants.TypeLastUpdate, "2027-05-05T16:15:08Z")

	geoResult := requireModuleResult(t, results, constants.TypeGeo, "City: FakeCity | Country: Fakeland (FC) | Lat/Lon: 10.123400, 20.567800")
	if geoResult.Category != constants.CategoryProperty {
		t.Fatalf("expected geo to be a property, got %q", geoResult.Category)
	}
}

func TestParseShodanAPIIPParsesEscapedSubjectAltName(t *testing.T) {
	targetIP := shodanTestAPIIPv4()
	wildcardSAN := "*.wild.sandbox.example.com"
	rawBody := loadShodanFixture(t, "ip_escaped_san.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody, targetIP)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	wildcardResult := requireModuleResult(t, exec.Results, constants.TypeWildcardSANDomain, wildcardSAN)
	if wildcardResult.Source != nil {
		t.Fatalf("expected wildcard SAN to be attached directly to target IP, got %+v", wildcardResult.Source)
	}
	requireModuleResult(t, exec.Results, constants.TypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, constants.TypeCertFingerprint, "sha1:00112233445566778899aabbccddeeff00112233", constants.TypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, constants.TypeCertFingerprint, "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", constants.TypePort, "443/tcp")
	assertShodanIPResultSource(t, exec.Results, constants.TypeCertIssuer, "O: Example Test CA | CN: Example Issuer | C: ZZ", constants.TypeWildcardSANDomain, wildcardSAN)
	assertShodanIPResultSource(t, exec.Results, constants.TypeCertNotAfter, "2027-07-20T19:44:15Z", constants.TypeWildcardSANDomain, wildcardSAN)
	assertShodanIPResultSource(t, exec.Results, constants.TypeTLSVersions, "TLSv1.2, TLSv1.3", constants.TypeWildcardSANDomain, wildcardSAN)
	requireModuleResult(t, exec.Results, constants.TypeSANDomain, "wild.sandbox.example.com")
	if _, ok := findModuleResult(exec.Results, constants.TypeSANDomain, "twild.sandbox.example.com"); ok {
		t.Fatalf("expected escaped SAN data to avoid bogus tnewton.ua result, got %+v", exec.Results)
	}
}

func TestParseShodanAPIIPSkipsDuplicateWebServerValue(t *testing.T) {
	targetIP := shodanTestAPIIPv4()
	rawBody := loadShodanFixture(t, "ip_duplicate_webserver.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody, targetIP)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	serviceResult := requireModuleResult(t, exec.Results, constants.TypeService, "nginx")
	if serviceResult.Source != nil {
		t.Fatalf("expected service to be anchored to IP, got %+v", serviceResult.Source)
	}
	if _, ok := findModuleResult(exec.Results, constants.TypeWebServer, "nginx"); ok {
		t.Fatalf("expected duplicate web_server value to be skipped, got %+v", exec.Results)
	}
	portResult := requireModuleResult(t, exec.Results, constants.TypePort, "443/tcp https")
	if portResult.Source == nil || portResult.Source.Type != constants.TypeService || portResult.Source.Value != "nginx" {
		t.Fatalf("expected port to be chained to service nginx, got %+v", portResult.Source)
	}

	assertShodanIPResultSource(t, exec.Results, constants.TypeHash, "3333333", constants.TypePort, "443/tcp https")
	assertShodanIPResultSource(t, exec.Results, constants.TypeCPE, "cpe:/a:f5:nginx", constants.TypePort, "443/tcp https")
	assertShodanIPResultSource(t, exec.Results, constants.TypeCPE23, "cpe:2.3:a:f5:nginx", constants.TypePort, "443/tcp https")
}

func TestAppendReverseIPHostnameResultKeepsInvalidPTRProperty(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}

	appendReverseIPHostnameResult(&exec, "invalid ptr hostname", "Synthetic PTR")

	result := requireModuleResultWithContext(t, exec.Results, constants.TypePTR, "invalid ptr hostname", "Synthetic PTR")
	if result.Category != constants.CategoryProperty {
		t.Fatalf("expected invalid PTR hostname to stay property, got %+v", result)
	}
	if len(result.Tags) > 0 {
		t.Fatalf("expected invalid PTR hostname to have no tags, got %v", result.Tags)
	}
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
	targetIP := shodanTestAPIIPv4()
	rawBody := loadShodanFixture(t, "ip_heartbleed.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody, targetIP)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	requireModuleResult(t, exec.Results, constants.TypePort, "443/tcp https")
	assertShodanIPResultSource(t, exec.Results, constants.TypeHeartbleed, "VULNERABLE", constants.TypePort, "443/tcp https")
}

func TestParseShodanAPIIPFallsBackToPortSource(t *testing.T) {
	targetIP := shodanTestAPIIPv4()
	rawBody := loadShodanFixture(t, "ip_port_fallback.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, rawBody, targetIP)
	if exec.Error != nil {
		t.Fatalf("unexpected parser error: %v", *exec.Error)
	}

	if _, ok := findModuleResult(exec.Results, constants.TypeService, "stun"); ok {
		t.Fatalf("expected module label to stay on port instead of creating service node, got %+v", exec.Results)
	}
	requireModuleResult(t, exec.Results, constants.TypePort, "3478/udp stun")
	assertShodanIPResultSource(t, exec.Results, constants.TypeHash, "1111111", constants.TypePort, "3478/udp stun")
	assertShodanIPResultSource(t, exec.Results, constants.TypeBannerTimestamp, "2026-05-04T18:19:25.001152", constants.TypePort, "3478/udp stun")
}

func TestGetShodanAPIIP(t *testing.T) {
	targetIP := shodanTestAPIIPv4()
	apiKey := shodanTestAPIKey()
	service := "FakeProduct 9.9"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case shodanTestPreflightPath():
			writeTestResponse(t, w, `{"query_credits":100}`)
		case "/shodan/host/" + targetIP:
			writeTestResponse(t, w, `{
				"asn": "AS99999",
				"tags": ["faketag"],
				"data": [{"port": 443, "transport": "tcp", "product": "FakeProduct", "version": "9.9", "hash": 2222222}]
			}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	originalBaseURL := shodanAPIBaseURL
	shodanAPIBaseURL = server.URL
	defer func() { shodanAPIBaseURL = originalBaseURL }()

	module := &shodanModule{apiKey: apiKey}
	module.lastReqTime = time.Now().Add(-2 * time.Second)

	exec := module.getShodanAPIIP(schema.Entity{Type: constants.TypeIP, Value: targetIP})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}
	if exec.RawData == "" {
		t.Fatal("expected raw data to be preserved")
	}

	requireModuleResult(t, exec.Results, constants.TypeASN, "99999")
	requireModuleResult(t, exec.Results, constants.TypeService, service)
	requireModuleResult(t, exec.Results, constants.TypeHash, "2222222")
}

func TestParseShodanAPIIPInvalidJSON(t *testing.T) {
	targetIP := shodanTestAPIIPv4()

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	parseShodanAPIIP(&exec, []byte(`{invalid json`), targetIP)
	if exec.Error == nil || !strings.Contains(*exec.Error, "unmarshal json") {
		t.Fatalf("expected unmarshal error, got %+v", exec.Error)
	}
}
