package shodan

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cdua-org/ReconSR/schema"
)

func TestParseShodanAPIDomain(t *testing.T) {
	rawBody := []byte(`{
		"data": [
			{"subdomain":"www","type":"A","value":"198.51.100.25"},
			{"subdomain":"www","type":"TXT","value":"v=spf1 -all"},
			{"subdomain":"mail","type":"MX","value":"mx.example.com"},
			{"subdomain":"cdn","type":"CNAME","value":"edge.example.net"},
			{"subdomain":"","type":"AAAA","value":"2001:db8::10"},
			{"subdomain":"ns1","type":"NS","value":"ns1.example.com"}
		]
	}`)

	exec := schema.ModuleExecution{Function: functionShodanAPIDomain}
	parseShodanAPIDomain(&exec, rawBody, testShodanAPIDomain)

	assertShodanDomainSubdomainChain(t, exec.Results)
	assertShodanDomainRootRecords(t, exec.Results)
	assertShodanDomainScopedRecords(t, exec.Results)
}

func assertShodanDomainSubdomainChain(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wwwSubdomain := requireModuleResult(t, results, resultTypeSubdomain, "www."+testShodanAPIDomain)
	if wwwSubdomain.Source != nil {
		t.Fatalf("expected direct subdomain relation, got %+v", wwwSubdomain.Source)
	}

	wwwIPv4 := requireModuleResult(t, results, entityTypeIPv4, "198.51.100.25")
	if wwwIPv4.Source == nil || wwwIPv4.Source.Type != resultTypeSubdomain || wwwIPv4.Source.Value != "www."+testShodanAPIDomain {
		t.Fatalf("expected A record to be linked to www subdomain, got %+v", wwwIPv4.Source)
	}

	wwwTXT := requireModuleResult(t, results, "txt", "v=spf1 -all")
	if wwwTXT.Source == nil || wwwTXT.Source.Type != resultTypeSubdomain || wwwTXT.Source.Value != "www."+testShodanAPIDomain {
		t.Fatalf("expected TXT record to be linked to www subdomain, got %+v", wwwTXT.Source)
	}
}

func assertShodanDomainRootRecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	rootIPv6 := requireModuleResult(t, results, entityTypeIPv6, "2001:db8::10")
	if rootIPv6.Source != nil {
		t.Fatalf("expected root AAAA record to stay linked to target, got %+v", rootIPv6.Source)
	}

	nsResult := requireModuleResult(t, results, "ns", "ns1.example.com")
	if nsResult.Source == nil || nsResult.Source.Type != resultTypeSubdomain || nsResult.Source.Value != "ns1."+testShodanAPIDomain {
		t.Fatalf("expected NS record to be linked to ns1 subdomain, got %+v", nsResult.Source)
	}
}

func assertShodanDomainScopedRecords(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	mxResult := requireModuleResult(t, results, "mx", "mx.example.com")
	if mxResult.Source == nil || mxResult.Source.Type != resultTypeSubdomain || mxResult.Source.Value != "mail."+testShodanAPIDomain {
		t.Fatalf("expected MX record to be linked to mail subdomain, got %+v", mxResult.Source)
	}
	if mxResult.OutOfScope {
		t.Fatal("expected in-scope MX target")
	}

	cnameResult := requireModuleResult(t, results, "cname", "edge.example.net")
	if !cnameResult.OutOfScope {
		t.Fatal("expected external CNAME target to be out of scope")
	}
}

func TestGetShodanAPIDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api-info":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"query_credits":1}`)); err != nil {
				t.Errorf("write error: %v", err)
			}
		case "/dns/domain/" + testShodanAPIDomain:
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

	module := &shodanModule{apiKey: testShodanAPIKey}
	module.lastReqTime = time.Now().Add(-2 * time.Second)

	exec := module.getShodanAPIDomain(schema.Entity{Type: entityTypeDomain, Value: testShodanAPIDomain})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}
	if exec.RawData == "" {
		t.Fatal("expected raw data to be preserved")
	}
	if module.queryCredits != 0 {
		t.Fatalf("expected credits to be decremented to 0, got %d", module.queryCredits)
	}

	requireModuleResult(t, exec.Results, resultTypeSubdomain, "www."+testShodanAPIDomain)
	requireModuleResult(t, exec.Results, entityTypeIPv4, "198.51.100.25")

	module.lastReqTime = time.Now().Add(-2 * time.Second)
	exhaustedExec := module.getShodanAPIDomain(schema.Entity{Type: entityTypeDomain, Value: testShodanAPIDomain})
	infoResult := requireModuleResult(t, exhaustedExec.Results, resultTypeInfo, "Shodan API key is invalid or query credits exhausted")
	if infoResult.Category != resultCategoryProperty {
		t.Fatalf("expected info result to be property, got %q", infoResult.Category)
	}
}
