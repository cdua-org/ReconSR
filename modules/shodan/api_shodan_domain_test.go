package shodan

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIDomain(t *testing.T) {
	rootDomainValue := "example.com"
	rawBody := []byte(`{
		"tags": ["tag1", "tag2"],
		"data": [
			{"subdomain":"www","type":"A","value":"198.51.100.25","last_seen":"2026-05-02T12:30:00.000000"},
			{"subdomain":"www","type":"TXT","value":"v=spf1 -all","last_seen":"2026-05-02T12:31:00.000000"},
			{"subdomain":"mail","type":"MX","value":"mx.example.com","options":{"priority":10},"last_seen":"2026-05-02T12:32:00.000000"},
			{"subdomain":"cdn","type":"CNAME","value":"edge.example.net","last_seen":"2026-05-02T12:33:00.000000"},
			{"subdomain":"","type":"AAAA","value":"2001:db8::10","last_seen":"2026-05-02T12:34:00.000000"},
			{"subdomain":"ns1","type":"NS","value":"ns1.example.com","last_seen":"2026-05-02T12:35:00.000000"},
			{"subdomain":"*","type":"A","value":"198.51.100.26","last_seen":"2026-05-02T12:36:00.000000"},
			{"subdomain":"*.dev","type":"A","value":"198.51.100.27","last_seen":"2026-05-02T12:37:00.000000"},
			{"subdomain":"","type":"SOA","value":"ns1.example.com","options":{"hostmaster":"dns.example.net","serial":1234567890,"refresh":10000,"retry":2400,"expires":604800,"minttl":1800},"last_seen":"2026-05-02T12:38:00.000000"},
			{"subdomain":"_sip._tcp","type":"SRV","value":"10 100 5060 sip.example.com","last_seen":"2026-05-02T12:39:00.000000"},
			{"subdomain":"","type":"CAA","value":"0 issue \"letsencrypt.org\"","last_seen":"2026-05-02T12:40:00.000000"},
			{"subdomain":"_http._tcp","type":"URI","value":"10 100 \"https://example.com/api\"","last_seen":"2026-05-02T12:41:00.000000"},
			{"subdomain":"sip","type":"NAPTR","value":"100 50 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.com.","last_seen":"2026-05-02T12:42:00.000000"},
			{"subdomain":"","type":"RP","value":"admin.example.com admin-txt.example.com","last_seen":"2026-05-02T12:43:00.000000"},
			{"subdomain":"host","type":"HIP","value":"2 2001:10... base64... rv1.example.net rv2.example.com","last_seen":"2026-05-02T12:44:00.000000"}
		]
	}`)

	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	parseShodanAPIDomain(&exec, rawBody, rootDomainValue)

	assertShodanDomainTags(t, exec.Results, rootDomainValue)
	assertShodanDomainSubdomainChain(t, exec.Results)
	assertShodanDomainRootRecords(t, exec.Results)
	assertShodanDomainMXRecords(t, exec.Results)
	assertShodanDomainCNAMERecords(t, exec.Results)
	assertShodanDomainWildcards(t, exec.Results)
	assertShodanDomainSOA(t, exec.Results)
	assertShodanDomainAdvancedRecords1(t, exec.Results)
	assertShodanDomainAdvancedRecords2(t, exec.Results)
	assertShodanDomainLastSeen(t, exec.Results, rootDomainValue)
}

func assertShodanDomainTags(t *testing.T, results []schema.ModuleResult, rootDomainValue string) {
	t.Helper()

	domainResult := requireModuleResult(t, results, constants.TypeDomain, rootDomainValue)
	if len(domainResult.Tags) != 2 || domainResult.Tags[0] != "tag1" || domainResult.Tags[1] != "tag2" {
		t.Fatalf("expected tags [tag1, tag2], got %v", domainResult.Tags)
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

	nsResult := requireModuleResultWithContext(t, results, constants.TypeNS, "ns1.example.com", "NS Record")
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

	mxHost := requireModuleResult(t, results, constants.TypeMXHost, "mx.example.com")
	if mxHost.Category != constants.CategoryNode {
		t.Fatalf("expected mx_host category to be node, got %q", mxHost.Category)
	}
	if mxHost.OutOfScope {
		t.Fatal("expected in-scope mx_host")
	}
}

func assertShodanDomainCNAMERecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	cnameResult := requireModuleResult(t, results, constants.TypeCNAMETarget, "edge.example.net")
	if !cnameResult.OutOfScope {
		t.Fatal("expected external CNAME target to be out of scope")
	}
	if cnameResult.Context != "CNAME Record" {
		t.Fatalf("expected CNAME Record context, got %q", cnameResult.Context)
	}
}

func assertShodanDomainWildcards(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wildcardDomain := requireModuleResult(t, results, constants.TypeWildcardDomain, "*.example.com")
	if wildcardDomain.Source != nil {
		t.Fatalf("expected direct wildcard domain relation, got %+v", wildcardDomain.Source)
	}

	wildcardIP := requireModuleResult(t, results, constants.TypeIPv4, "198.51.100.26")
	if wildcardIP.Source == nil || wildcardIP.Source.Type != constants.TypeWildcardDomain || wildcardIP.Source.Value != "*.example.com" {
		t.Fatalf("expected wildcard A record linked to wildcard_domain, got %+v", wildcardIP.Source)
	}

	wildcardSubdomain := requireModuleResult(t, results, constants.TypeWildcardSubdomain, "*.dev.example.com")
	if wildcardSubdomain.Source != nil {
		t.Fatalf("expected direct wildcard subdomain relation, got %+v", wildcardSubdomain.Source)
	}
}

func assertShodanDomainSOA(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	soaRaw := requireModuleResult(t, results, constants.TypeSOA, "ns1.example.com dns.example.net 1234567890 10000 2400 604800 1800")
	if soaRaw.Source != nil {
		t.Fatalf("expected root SOA linked to target, got %+v", soaRaw.Source)
	}
	if soaRaw.Category != constants.CategoryProperty {
		t.Fatalf("expected SOA category to be property, got %q", soaRaw.Category)
	}

	soaSerial := requireModuleResultWithContext(t, results, constants.TypeSOA, "1234567890", "Serial")
	if soaSerial.Source != nil {
		t.Fatalf("expected root SOA serial linked to target, got %+v", soaSerial.Source)
	}

	primaryNS := requireModuleResultWithContext(t, results, constants.TypeNS, "ns1.example.com", "Primary NS")
	if primaryNS.Source != nil {
		t.Fatalf("expected SOA primary NS linked to target, got %+v", primaryNS.Source)
	}

	email := requireModuleResultWithContext(t, results, constants.TypeEmail, "dns@example.net", "Responsible Email")
	if email.Source != nil {
		t.Fatalf("expected SOA email linked to target, got %+v", email.Source)
	}
	if !email.OutOfScope {
		t.Fatal("expected SOA responsible email to be out of scope")
	}
}

func assertShodanDomainAdvancedRecords1(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	srvHost := requireModuleResult(t, results, constants.TypeSRVHost, "sip.example.com")
	if srvHost.Category != constants.CategoryNode || srvHost.OutOfScope {
		t.Fatal("expected in-scope srv_host node")
	}

	caaAuth := requireModuleResultWithContext(t, results, constants.TypeCertAuthority, "letsencrypt.org", "CAA Record")
	if caaAuth.Category != constants.CategoryNode || !caaAuth.OutOfScope {
		t.Fatal("expected out-of-scope cert_authority node")
	}

	uriEndpoint := requireModuleResultWithContext(t, results, constants.TypeURL, "https://example.com/api", "URI Endpoint")
	if uriEndpoint.Category != constants.CategoryProperty {
		t.Fatal("expected url property")
	}
}

func assertShodanDomainAdvancedRecords2(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	naptrTarget := requireModuleResultWithContext(t, results, constants.TypeNAPTRTarget, "_sip._udp.example.com", "NAPTR Target")
	if naptrTarget.Category != constants.CategoryNode || naptrTarget.OutOfScope {
		t.Fatal("expected in-scope naptr_target node")
	}

	rpEmail := requireModuleResultWithContext(t, results, constants.TypeEmail, "admin@example.com", "RP Administrator Email")
	if rpEmail.Category != constants.CategoryNode || rpEmail.OutOfScope {
		t.Fatal("expected in-scope email node for RP")
	}
	rpDomain := requireModuleResultWithContext(t, results, constants.TypeRPDomain, "admin-txt.example.com", "RP TXT Reference Domain")
	if rpDomain.Category != constants.CategoryNode || rpDomain.OutOfScope {
		t.Fatal("expected in-scope rp_domain node")
	}

	hipServer1 := requireModuleResultWithContext(t, results, constants.TypeHIPServer, "rv1.example.net", "HIP Rendezvous Server")
	if hipServer1.Category != constants.CategoryNode || !hipServer1.OutOfScope {
		t.Fatal("expected out-of-scope hip_server node")
	}
	hipServer2 := requireModuleResultWithContext(t, results, constants.TypeHIPServer, "rv2.example.com", "HIP Rendezvous Server")
	if hipServer2.Category != constants.CategoryNode || hipServer2.OutOfScope {
		t.Fatal("expected in-scope hip_server node")
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

	soaLastSeen := findModuleResultBySource(results, constants.TypeLastSeen, constants.TypeSOA, "ns1.example.com dns.example.net 1234567890 10000 2400 604800 1800")
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
	rootDomainValue := "example.com"
	apiKey := shodanTestAPIKey()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api-info":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"query_credits":1}`)); err != nil {
				t.Errorf("write error: %v", err)
			}
		case "/dns/domain/" + rootDomainValue:
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"data":[{"subdomain":"www","type":"A","value":"198.51.100.25"}]}`)); err != nil {
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

	requireModuleResult(t, exec.Results, constants.TypeSubdomain, "www.example.com")
	requireModuleResult(t, exec.Results, constants.TypeIPv4, "198.51.100.25")

	module.lastReqTime = time.Now().Add(-2 * time.Second)
	exhaustedExec := module.getShodanAPIDomain(schema.Entity{Type: constants.TypeDomain, Value: rootDomainValue})
	infoResult := requireModuleResult(t, exhaustedExec.Results, constants.TypeInfo, "Shodan API key is invalid or query credits exhausted")
	if infoResult.Category != constants.CategoryProperty {
		t.Fatalf("expected info result to be property, got %q", infoResult.Category)
	}
}
