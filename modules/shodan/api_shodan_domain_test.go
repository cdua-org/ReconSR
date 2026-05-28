package shodan

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
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
	assertShodanDomainSPF(t, exec.Results)
	assertShodanDomainRootRecords(t, exec.Results)
	assertShodanDomainMXRecords(t, exec.Results)
	assertShodanDomainCNAMERecords(t, exec.Results)
	assertShodanDomainWildcards(t, exec.Results)
	assertShodanDomainSOA(t, exec.Results)
	assertShodanDomainSRV(t, exec.Results)
	assertShodanDomainCAA(t, exec.Results)
	assertShodanDomainURI(t, exec.Results)
	assertShodanDomainNAPTR(t, exec.Results)
	assertShodanDomainRP(t, exec.Results)
	assertShodanDomainHIP(t, exec.Results)
	assertShodanDomainInvalidSubdomains(t, exec.Results)
	assertShodanDomainLastSeen(t, exec.Results)
	assertShodanDomainSelfReferentialSkipped(t, exec.Results, rootDomainValue)

	wwwSubdomain := requireModuleResult(t, exec.Results, constants.TypeSubdomain, "www.example.com")
	if !slices.Contains(wwwSubdomain.Tags, constants.TagPDNS) {
		t.Fatalf("expected passive_dns tag, got %v", wwwSubdomain.Tags)
	}
	if slices.Contains(wwwSubdomain.Tags, constants.TagHistorical) {
		t.Fatalf("did not expect historical tag, got %v", wwwSubdomain.Tags)
	}
}

func TestParseShodanAPIDomainHistorical(t *testing.T) {
	resolver.ShodanDomainHistory = true
	defer func() { resolver.ShodanDomainHistory = false }()

	rootDomainValue := "example.net"
	rawBody := loadShodanFixture(t, "domain.json")

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	parseShodanAPIDomain(&exec, rawBody, rootDomainValue)

	wwwSubdomain := requireModuleResult(t, exec.Results, constants.TypeSubdomain, "www.example.net")
	if !slices.Contains(wwwSubdomain.Tags, constants.TagHistorical) {
		t.Fatalf("expected historical tag, got %v", wwwSubdomain.Tags)
	}
	if !slices.Contains(wwwSubdomain.Tags, constants.TagPDNS) {
		t.Fatalf("expected passive_dns tag, got %v", wwwSubdomain.Tags)
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	rootDomainValue := "localid-chain.example.net"
	apiKey := shodanTestAPIKey()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case shodanTestPreflightPath():
			writeTestResponse(t, w, `{"query_credits":1}`)
		case "/dns/domain/" + rootDomainValue:
			writeTestResponse(t, w, `{"data":[{"subdomain":"www","type":"A","value":"198.51.100.25"}, {"subdomain":"mail","type":"MX","value":"mail.localid-chain.example.net"}]}`)
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

	if len(exec.Results) < 2 {
		t.Fatalf("Expected multiple results to verify chaining, got %d", len(exec.Results))
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}
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
}

func assertShodanDomainSPF(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	spfValue := "v=spf1 ip4:198.51.100.30 include:spf.example.org -all"
	wwwSPF := requireModuleResult(t, results, constants.TypeSPF, spfValue)
	if wwwSPF.Source == nil || wwwSPF.Source.Type != constants.TypeSubdomain {
		t.Fatalf("expected SPF record linked to a subdomain, got %+v", wwwSPF.Source)
	}
	if wwwSPF.Category != constants.CategoryProperty {
		t.Fatalf("expected SPF category to be property, got %q", wwwSPF.Category)
	}

	spfIP := requireModuleResultWithTag(t, results, constants.TypeIPv4, "198.51.100.30", constants.TagSPF)
	if spfIP.Source == nil || spfIP.Source.Type != constants.TypeSPF || spfIP.Source.Value != spfValue {
		t.Fatalf("expected SPF IP linked to SPF record, got %+v", spfIP.Source)
	}
	if spfIP.Context != "SPF ip4" {
		t.Fatalf("expected SPF ip4 context, got %q", spfIP.Context)
	}

	spfInclude := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "spf.example.org", constants.TagSPF)
	if spfInclude.Source == nil || spfInclude.Source.Type != constants.TypeSPF || spfInclude.Source.Value != spfValue {
		t.Fatalf("expected SPF include linked to SPF record, got %+v", spfInclude.Source)
	}
	if !spfInclude.OutOfScope {
		t.Fatal("expected SPF include domain to be out of scope")
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
	if mxHost.Source == nil || mxHost.Source.Type != constants.TypeMX || mxHost.Source.Value != "10 mx.example.com" {
		t.Fatalf("expected mx host linked to MX record, got %+v", mxHost.Source)
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

	primaryNS := findModuleResultBySource(results, constants.TypeSubdomain, constants.TypeSOA, soaRaw.Value)
	if primaryNS == nil || primaryNS.Value != "ns1.example.com" {
		t.Fatalf("expected SOA primary NS linked to SOA property")
	}
	if !slices.Contains(primaryNS.Tags, constants.TagNS) {
		t.Fatalf("expected SOA primary NS to have tag %q, got %v", constants.TagNS, primaryNS.Tags)
	}

	email := findModuleResultBySource(results, constants.TypeEmail, constants.TypeSOA, soaRaw.Value)
	if email == nil || email.Value != "dns@example.net" {
		t.Fatalf("expected SOA email linked to SOA property")
	}
	if !email.OutOfScope {
		t.Fatal("expected SOA responsible email to be out of scope")
	}
}

func assertShodanDomainSRV(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	srvProp := requireModuleResult(t, results, constants.TypeSRV, "10 100 5060 sip.example.com")
	if srvProp.Category != constants.CategoryProperty {
		t.Fatalf("expected srv category to be property, got %q", srvProp.Category)
	}

	srvHost := requireModuleResult(t, results, constants.TypeSubdomain, "sip.example.com")
	if srvHost.Category != constants.CategoryNode || srvHost.OutOfScope {
		t.Fatal("expected in-scope srv host node")
	}
	if !slices.Contains(srvHost.Tags, constants.TagSRV) {
		t.Fatalf("expected srv host to have tag %q, got tags %v", constants.TagSRV, srvHost.Tags)
	}
	if srvHost.Source == nil || srvHost.Source.Type != constants.TypeSRV || srvHost.Source.Value != srvProp.Value {
		t.Fatalf("expected srv host to be linked to srv property, got %+v", srvHost.Source)
	}
}

func assertShodanDomainCAA(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	caaAuth := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "ca.example.net", constants.TagCAA)
	if caaAuth.Category != constants.CategoryNode || !caaAuth.OutOfScope {
		t.Fatal("expected out-of-scope cert_authority node")
	}
	if !slices.Contains(caaAuth.Tags, constants.TagCAA) {
		t.Fatalf("expected cert_authority to have tag %q, got tags %v", constants.TagCAA, caaAuth.Tags)
	}
}

func assertShodanDomainURI(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	uriEndpoint := requireModuleResult(t, results, constants.TypeURL, "https://example.com/api")
	if uriEndpoint.Category != constants.CategoryProperty {
		t.Fatal("expected url property")
	}
	if uriEndpoint.Source == nil || uriEndpoint.Source.Type != constants.TypeURI {
		t.Fatalf("expected URI endpoint to be linked to URI record, got %+v", uriEndpoint.Source)
	}
}

func assertShodanDomainNAPTR(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	naptrTarget := requireModuleResultWithContext(t, results, constants.TypeSubdomain, "sip.example.com", "NAPTR Target (_sip._tcp.sip.example.com.)")
	if naptrTarget.Category != constants.CategoryNode || naptrTarget.OutOfScope {
		t.Fatal("expected in-scope naptr target node for valid subdomain")
	}

	naptrTarget2 := requireModuleResultWithContext(t, results, constants.TypeDomain, "example.net", "NAPTR Target (_sip._udp.example.net.)")
	if naptrTarget2.Category != constants.CategoryNode || !naptrTarget2.OutOfScope {
		t.Fatal("expected out-of-scope naptr target node for external domain")
	}
	if !slices.Contains(naptrTarget.Tags, constants.TagNAPTR) {
		t.Fatalf("expected naptr target to have tag %q, got tags %v", constants.TagNAPTR, naptrTarget.Tags)
	}
	if naptrTarget.Source == nil || naptrTarget.Source.Type != constants.TypeNAPTR {
		t.Fatalf("expected naptr target to be linked to naptr service or record, got %+v", naptrTarget.Source)
	}
}

func TestShodanNAPTRSelfReferentialSkip(t *testing.T) {
	exec := &schema.ModuleExecution{}
	sourceDomain := &schema.EntityRef{Type: constants.TypeSubdomain, Value: "node.example.org"}
	rawNaptr := "100 50 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.org."

	gen := modutil.NewLocalIDGenerator()
	appendShodanNAPTRResult(exec, rawNaptr, "example.org", sourceDomain, gen)

	for _, res := range exec.Results {
		if res.Type == constants.TypeDomain && res.Value == "example.org" {
			t.Fatal("expected self-referential NAPTR target to NOT be emitted as a node")
		}
	}
}

func TestAppendShodanNAPTRResultRegexp(t *testing.T) {
	exec := &schema.ModuleExecution{}
	sourceDomain := &schema.EntityRef{Type: constants.TypeDomain, Value: "example.edu"}
	rawNaptr := "10 100 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.edu!\" ."

	gen := modutil.NewLocalIDGenerator()
	ref := appendShodanNAPTRResult(exec, rawNaptr, "example.edu", sourceDomain, gen)

	if ref == nil || ref.Type != constants.TypeNAPTR {
		t.Fatalf("expected ref type NAPTR, got %+v", ref)
	}

	regexpProp := requireModuleResultWithContext(t, exec.Results, constants.TypeNAPTR, "!^.*$!sip:info@example.edu!", "NAPTR Regexp")
	if regexpProp.Source == nil || regexpProp.Source.Value != "E2U+sip" {
		t.Fatalf("expected regexp to link to service, got %+v", regexpProp.Source)
	}

	targetProp := requireModuleResultWithContext(t, exec.Results, constants.TypeURL, "sip:info@example.edu", "NAPTR Regexp Target")
	if targetProp.Source == nil || targetProp.Source.Value != "!^.*$!sip:info@example.edu!" {
		t.Fatalf("expected target to link to regexp, got %+v", targetProp.Source)
	}
}

func assertShodanDomainRP(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	rpEmail := requireModuleResult(t, results, constants.TypeEmail, "admin@example.com")
	if rpEmail.Category != constants.CategoryNode || rpEmail.OutOfScope {
		t.Fatal("expected in-scope email node for RP")
	}
	rpDomain := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "admin-txt.example.com", constants.TagRP)
	if rpDomain.Category != constants.CategoryNode || rpDomain.OutOfScope {
		t.Fatal("expected in-scope RP domain node")
	}
	if !slices.Contains(rpDomain.Tags, constants.TagRP) {
		t.Fatalf("expected RP domain to have tag %q, got tags %v", constants.TagRP, rpDomain.Tags)
	}
}

func assertShodanDomainHIP(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	hipServer1 := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "rv1.example.net", constants.TagHIP)
	if hipServer1.Category != constants.CategoryNode || !hipServer1.OutOfScope {
		t.Fatal("expected out-of-scope hip_server node")
	}
	if !slices.Contains(hipServer1.Tags, constants.TagHIP) {
		t.Fatalf("expected hip_server1 to have tag %q, got tags %v", constants.TagHIP, hipServer1.Tags)
	}
	hipServer2 := requireModuleResultWithTag(t, results, constants.TypeSubdomain, "rv2.example.com", constants.TagHIP)
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

func assertShodanDomainLastSeen(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wwwIPLastSeen := findModuleResultBySource(results, constants.TypeDate, constants.TypeIPv4, "198.51.100.25")
	if wwwIPLastSeen == nil {
		t.Fatal("expected last_seen for www A record")
	}
	if wwwIPLastSeen.Value != "Last Seen: 2026-05-02T12:30:00.000000" {
		t.Fatalf("expected www IP last_seen 2026-05-02T12:30:00.000000, got %q", wwwIPLastSeen.Value)
	}

	mxLastSeen := findModuleResultBySource(results, constants.TypeDate, constants.TypeMX, "10 mx.example.com")
	if mxLastSeen == nil {
		t.Fatal("expected last_seen for MX record")
	}
	if mxLastSeen.Value != "Last Seen: 2026-05-02T12:32:00.000000" {
		t.Fatalf("expected MX last_seen 2026-05-02T12:32:00.000000, got %q", mxLastSeen.Value)
	}

	soaLastSeen := findModuleResultBySource(results, constants.TypeDate, constants.TypeSOA, "ns1.example.com. dns.example.net. 1234567890 10000 2400 604800 1800")
	if soaLastSeen == nil {
		t.Fatal("expected last_seen for SOA record")
	}
	if soaLastSeen.Value != "Last Seen: 2026-05-02T12:38:00.000000" {
		t.Fatalf("expected SOA last_seen 2026-05-02T12:38:00.000000, got %q", soaLastSeen.Value)
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

func assertShodanDomainSelfReferentialSkipped(t *testing.T, results []schema.ModuleResult, target string) {
	t.Helper()

	for _, res := range results {
		if res.Category == constants.CategoryNode && res.Value == target {
			if slices.Contains(res.Tags, constants.TagWildcard) {
				continue
			}
			t.Fatalf("found unexpected self-referential node: %+v", res)
		}
	}
}
