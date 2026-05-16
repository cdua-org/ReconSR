package shodan

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIDomain(t *testing.T) {
	rootDomainValue := "example.com"
	rawBody := loadShodanFixture(t, "domain.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	parseShodanAPIDomain(&exec, rawBody, rootDomainValue)

	requireTagPropertyResults(t, exec.Results, "tag1", "tag2")
	assertShodanDomainSubdomainChain(t, exec.Results)
	assertShodanDomainRootRecords(t, exec.Results)
	assertShodanDomainMXRecords(t, exec.Results)
	assertShodanDomainCNAMERecords(t, exec.Results)
	assertShodanDomainWildcards(t, exec.Results)
	assertShodanDomainSOA(t, exec.Results)
	assertShodanDomainAdvancedRecords1(t, exec.Results)
	assertShodanDomainAdvancedRecords2(t, exec.Results)
	assertShodanDomainInvalidSubdomains(t, exec.Results)
	assertShodanDomainLastSeen(t, exec.Results, rootDomainValue)
}

func assertShodanDomainSubdomainChain(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wwwSubdomainValue := "www.example.com"
	wwwSubdomain := requireModuleResult(t, results, constants.TypeSubdomain, wwwSubdomainValue)
	if wwwSubdomain.Source != nil {
		t.Fatalf("expected direct subdomain relation, got %+v", wwwSubdomain.Source)
	}

	wwwIPv4 := requireModuleResult(t, results, constants.TypeIPv4, "198.51.100.25")
	if wwwIPv4.Source == nil || wwwIPv4.Source.Type != constants.TypeSubdomain || wwwIPv4.Source.Value != wwwSubdomainValue {
		t.Fatalf("expected A record linked to www subdomain, got %+v", wwwIPv4.Source)
	}
	if wwwIPv4.Context != "A/AAAA Record" {
		t.Fatalf("expected A/AAAA Record context, got %q", wwwIPv4.Context)
	}

	wwwSPF := requireModuleResult(t, results, constants.TypeSPF, "v=spf1 -all")
	if wwwSPF.Source == nil || wwwSPF.Source.Type != constants.TypeSubdomain || wwwSPF.Source.Value != wwwSubdomainValue {
		t.Fatalf("expected SPF record linked to www subdomain, got %+v", wwwSPF.Source)
	}
	if wwwSPF.Category != constants.CategoryProperty {
		t.Fatalf("expected SPF category to be property, got %q", wwwSPF.Category)
	}
}

func assertShodanDomainRootRecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	rootIPv6 := requireModuleResult(t, results, constants.TypeIPv6, "2001:db8::10")
	if rootIPv6.Source != nil {
		t.Fatalf("expected root AAAA record linked to target, got %+v", rootIPv6.Source)
	}

	nsResult := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "ns1.example.com", constants.TagNS)
	if nsResult.Source == nil || nsResult.Source.Type != constants.TypeSubdomain || nsResult.Source.Value != "ns1.example.com" {
		t.Fatalf("expected NS record linked to ns1 subdomain, got %+v", nsResult.Source)
	}
}

func assertShodanDomainMXRecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	mxProp := requireModuleResult(t, results, constants.TypeMX, "10 mx.example.com")
	if mxProp.Category != constants.CategoryProperty {
		t.Fatalf("expected MX category to be property, got %q", mxProp.Category)
	}
	if mxProp.Source == nil || mxProp.Source.Type != constants.TypeSubdomain || mxProp.Source.Value != "mail.example.com" {
		t.Fatalf("expected MX property linked to mail subdomain, got %+v", mxProp.Source)
	}

	mxHost := requireModuleResult(t, results, constants.TypeSubdomain, "mx.example.com")
	if mxHost.Category != constants.CategoryNode {
		t.Fatalf("expected mx host category to be node, got %q", mxHost.Category)
	}
	if !slices.Contains(mxHost.Tags, constants.TagMX) {
		t.Fatalf("expected mx host to have tag %q, got tags %v", constants.TagMX, mxHost.Tags)
	}
	if mxHost.OutOfScope {
		t.Fatal("expected in-scope mx host")
	}
}

func assertShodanDomainCNAMERecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	cnameResult := requireModuleResult(t, results, constants.TypeSubdomain, "edge.example.net")
	if !cnameResult.OutOfScope {
		t.Fatal("expected external CNAME target to be out of scope")
	}
	if !slices.Contains(cnameResult.Tags, constants.TagCNAME) {
		t.Fatalf("expected cname target to have tag %q, got tags %v", constants.TagCNAME, cnameResult.Tags)
	}
	if cnameResult.Context != "CNAME Record" {
		t.Fatalf("expected CNAME Record context, got %q", cnameResult.Context)
	}
}

func assertShodanDomainWildcards(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wildcardDomain := requireModuleResultWithTag(t, results, constants.TypeDomain, "example.com", constants.TagWildcard)
	if wildcardDomain.Source != nil {
		t.Fatalf("expected direct wildcard domain relation, got %+v", wildcardDomain.Source)
	}
	if wildcardDomain.Context != "*.example.com" {
		t.Fatalf("expected wildcard domain context, got %q", wildcardDomain.Context)
	}

	wildcardIP := requireModuleResult(t, results, constants.TypeIPv4, "198.51.100.26")
	if wildcardIP.Source == nil || wildcardIP.Source.Type != constants.TypeDomain || wildcardIP.Source.Value != "example.com" {
		t.Fatalf("expected wildcard A record linked to tagged domain, got %+v", wildcardIP.Source)
	}

	wildcardSubdomain := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "dev.example.com", constants.TagWildcard)
	if wildcardSubdomain.Source != nil {
		t.Fatalf("expected direct wildcard subdomain relation, got %+v", wildcardSubdomain.Source)
	}
	if wildcardSubdomain.Context != "*.dev.example.com" {
		t.Fatalf("expected wildcard subdomain context, got %q", wildcardSubdomain.Context)
	}
}

func assertShodanDomainSOA(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	soaRaw := requireModuleResult(t, results, constants.TypeSOA, "ns1.example.com. dns.example.net. 1234567890 10000 2400 604800 1800")
	if soaRaw.Source != nil {
		t.Fatalf("expected root SOA linked to target, got %+v", soaRaw.Source)
	}
	if soaRaw.Category != constants.CategoryProperty {
		t.Fatalf("expected SOA category to be property, got %q", soaRaw.Category)
	}

	soaSerial := requireModuleResultWithContext(t, results, constants.TypeSOA, "1234567890", "Serial")
	if soaSerial.Source == nil || soaSerial.Source.Type != constants.TypeSOA || soaSerial.Source.Value != soaRaw.Value {
		t.Fatalf("expected SOA serial linked to SOA property, got %+v", soaSerial.Source)
	}

	primaryNS := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "ns1.example.com", "Primary NS")
	if !slices.Contains(primaryNS.Tags, constants.TagNS) {
		t.Fatalf("expected SOA primary NS to have tag %q, got %v", constants.TagNS, primaryNS.Tags)
	}
	if primaryNS.Source == nil || primaryNS.Source.Type != constants.TypeSOA || primaryNS.Source.Value != soaRaw.Value {
		t.Fatalf("expected SOA primary NS linked to SOA property, got %+v", primaryNS.Source)
	}

	email := requireModuleResultWithContext(t, results, constants.TypeEmail, "dns@example.net", "Responsible Email")
	if email.Source == nil || email.Source.Type != constants.TypeSOA || email.Source.Value != soaRaw.Value {
		t.Fatalf("expected SOA email linked to SOA property, got %+v", email.Source)
	}
	if !email.OutOfScope {
		t.Fatal("expected SOA responsible email to be out of scope")
	}
}

func assertShodanDomainAdvancedRecords1(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	srvHost := requireModuleResult(t, results, constants.TypeSubdomain, "sip.example.com")
	if srvHost.Category != constants.CategoryNode || srvHost.OutOfScope {
		t.Fatal("expected in-scope srv host node")
	}
	if !slices.Contains(srvHost.Tags, constants.TagSRV) {
		t.Fatalf("expected srv host to have tag %q, got tags %v", constants.TagSRV, srvHost.Tags)
	}

	caaAuth := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "ca.example.net", "Authorized CA (issue)")
	if caaAuth.Category != constants.CategoryNode || !caaAuth.OutOfScope {
		t.Fatal("expected out-of-scope cert_authority node")
	}
	if !slices.Contains(caaAuth.Tags, constants.TagCAA) {
		t.Fatalf("expected cert_authority to have tag %q, got tags %v", constants.TagCAA, caaAuth.Tags)
	}

	uriEndpoint := requireModuleResultWithContext(t, results, constants.TypeURL, "https://example.com/api", "URI Endpoint")
	if uriEndpoint.Category != constants.CategoryProperty {
		t.Fatal("expected url property")
	}
}

func assertShodanDomainAdvancedRecords2(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	naptrTarget := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "_sip._udp.example.com", "NAPTR Target")
	if naptrTarget.Category != constants.CategoryNode || naptrTarget.OutOfScope {
		t.Fatal("expected in-scope naptr target node")
	}
	if !slices.Contains(naptrTarget.Tags, constants.TagNAPTR) {
		t.Fatalf("expected naptr target to have tag %q, got tags %v", constants.TagNAPTR, naptrTarget.Tags)
	}

	rpEmail := requireModuleResultWithContext(t, results, constants.TypeEmail, "admin@example.com", "RP Administrator Email")
	if rpEmail.Category != constants.CategoryNode || rpEmail.OutOfScope {
		t.Fatal("expected in-scope email node for RP")
	}
	rpDomain := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "admin-txt.example.com", "RP TXT Reference Domain")
	if rpDomain.Category != constants.CategoryNode || rpDomain.OutOfScope {
		t.Fatal("expected in-scope RP domain node")
	}
	if !slices.Contains(rpDomain.Tags, constants.TagRP) {
		t.Fatalf("expected RP domain to have tag %q, got tags %v", constants.TagRP, rpDomain.Tags)
	}

	hipServer1 := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "rv1.example.net", "HIP Rendezvous Server")
	if hipServer1.Category != constants.CategoryNode || !hipServer1.OutOfScope {
		t.Fatal("expected out-of-scope hip_server node")
	}
	if !slices.Contains(hipServer1.Tags, constants.TagHIP) {
		t.Fatalf("expected hip_server1 to have tag %q, got tags %v", constants.TagHIP, hipServer1.Tags)
	}
	hipServer2 := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "rv2.example.com", "HIP Rendezvous Server")
	if hipServer2.Category != constants.CategoryNode || hipServer2.OutOfScope {
		t.Fatal("expected in-scope hip_server node")
	}
	if !slices.Contains(hipServer2.Tags, constants.TagHIP) {
		t.Fatalf("expected hip_server2 to have tag %q, got tags %v", constants.TagHIP, hipServer2.Tags)
	}
}

func assertShodanDomainInvalidSubdomains(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	if _, ok := findModuleResult(results, constants.TypeSubdomain, "invalid_name.scripts.example.com"); ok {
		t.Fatal("expected no subdomain node for invalid hostname invalid_name.scripts.example.com")
	}

	invalidRecordIPv4 := requireModuleResult(t, results, constants.TypeIPv4, "198.51.100.99")
	if invalidRecordIPv4.Source != nil {
		t.Fatalf("expected IPv4 from invalid subdomain to be linked to root domain, got %+v", invalidRecordIPv4.Source)
	}

	if _, ok := findModuleResult(results, constants.TypeSubdomain, "_fake.service.media.example.com"); ok {
		t.Fatal("expected no subdomain node for invalid hostname _fake.service.media.example.com")
	}

	invalidRecordTXT := requireModuleResult(t, results, constants.TypeTXT, "some-txt-record")
	if invalidRecordTXT.Source != nil {
		t.Fatalf("expected TXT property from invalid subdomain to be linked to root domain, got %+v", invalidRecordTXT.Source)
	}
}

func assertShodanDomainLastSeen(t *testing.T, results []schema.ModuleResult, rootDomainValue string) {
	t.Helper()

	wwwSubdomainValue := "www.example.com"
	mailSubdomainValue := "mail.example.com"

	wwwIPLastSeen := findModuleResultBySource(results, constants.TypeLastSeen, constants.TypeIPv4, "198.51.100.25")
	if wwwIPLastSeen == nil {
		t.Fatal("expected last_seen for www A record")
	}
	if wwwIPLastSeen.Value != "2026-05-02T12:30:00.000000" {
		t.Fatalf("expected www IP last_seen 2026-05-02T12:30:00.000000, got %q", wwwIPLastSeen.Value)
	}
	if wwwIPLastSeen.Context != wwwSubdomainValue {
		t.Fatalf("expected last_seen context %s, got %q", wwwSubdomainValue, wwwIPLastSeen.Context)
	}

	mxLastSeen := findModuleResultBySource(results, constants.TypeLastSeen, constants.TypeMX, "10 mx.example.com")
	if mxLastSeen == nil {
		t.Fatal("expected last_seen for MX record")
	}
	if mxLastSeen.Value != "2026-05-02T12:32:00.000000" {
		t.Fatalf("expected MX last_seen 2026-05-02T12:32:00.000000, got %q", mxLastSeen.Value)
	}
	if mxLastSeen.Context != mailSubdomainValue {
		t.Fatalf("expected last_seen context %s, got %q", mailSubdomainValue, mxLastSeen.Context)
	}

	soaLastSeen := findModuleResultBySource(results, constants.TypeLastSeen, constants.TypeSOA, "ns1.example.com. dns.example.net. 1234567890 10000 2400 604800 1800")
	if soaLastSeen == nil {
		t.Fatal("expected last_seen for SOA record")
	}
	if soaLastSeen.Value != "2026-05-02T12:38:00.000000" {
		t.Fatalf("expected SOA last_seen 2026-05-02T12:38:00.000000, got %q", soaLastSeen.Value)
	}
	if soaLastSeen.Context != rootDomainValue {
		t.Fatalf("expected last_seen context %s, got %q", rootDomainValue, soaLastSeen.Context)
	}
}

func TestGetShodanAPIDomain(t *testing.T) {
	rootDomainValue := "example.net"
	apiKey := shodanTestAPIKey()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case shodanTestPreflightPath():
			writeTestResponse(t, w, `{"query_credits":1}`)
		case "/dns/domain/" + rootDomainValue:
			writeTestResponse(t, w, `{"data":[{"subdomain":"www","type":"A","value":"198.51.100.25"}]}`)
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

	exec := module.getShodanAPIDomain(schema.Entity{Type: constants.TypeDomain, Value: rootDomainValue})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}
	if exec.RawData == "" {
		t.Fatal("expected raw data to be preserved")
	}
	if module.queryCredits != 0 {
		t.Fatalf("expected credits to be decremented to 0, got %d", module.queryCredits)
	}

	requireModuleResult(t, exec.Results, constants.TypeSubdomain, "www.example.net")
	requireModuleResult(t, exec.Results, constants.TypeIPv4, "198.51.100.25")

	module.lastReqTime = time.Now().Add(-2 * time.Second)
	exhaustedExec := module.getShodanAPIDomain(schema.Entity{Type: constants.TypeDomain, Value: rootDomainValue})
	infoResult := requireModuleResult(t, exhaustedExec.Results, constants.TypeInfo, "Shodan API key is invalid or query credits exhausted")
	if infoResult.Category != constants.CategoryProperty {
		t.Fatalf("expected info result to be property, got %q", infoResult.Category)
	}
}

func TestGetShodanAPIDomainPagination(t *testing.T) {
	resolver.ShodanMaxDomainPages = 2
	defer func() { resolver.ShodanMaxDomainPages = 1 }()

	rootDomainValue := "example.org"
	apiKey := shodanTestAPIKey()

	var reqCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case shodanTestPreflightPath():
			writeTestResponse(t, w, `{"query_credits":5}`)
		case "/dns/domain/" + rootDomainValue:
			reqCount++
			switch r.URL.Query().Get("page") {
			case "":
				writeTestResponse(t, w, `{"data":[{"subdomain":"page1","type":"A","value":"198.51.100.1"}],"more":true}`)
			case "2":
				writeTestResponse(t, w, `{"data":[{"subdomain":"page2","type":"A","value":"198.51.100.2"}],"more":false}`)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
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

	exec := module.getShodanAPIDomain(schema.Entity{Type: constants.TypeDomain, Value: rootDomainValue})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	if reqCount != 2 {
		t.Fatalf("expected 2 page requests, got %d", reqCount)
	}

	if module.queryCredits != 3 {
		t.Fatalf("expected 3 credits remaining, got %d", module.queryCredits)
	}

	requireModuleResult(t, exec.Results, constants.TypeSubdomain, "page1.example.org")
	requireModuleResult(t, exec.Results, constants.TypeSubdomain, "page2.example.org")
}
