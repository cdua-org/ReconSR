package netlas

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func newTestModule(t *testing.T, apiKey string) *netlasModule {
	t.Helper()
	m, ok := New().(*netlasModule)
	if !ok {
		t.Fatal("expected *netlasModule")
	}
	m.apiKey = apiKey
	return m
}

func writeMock(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	if _, err := w.Write(data); err != nil {
		t.Errorf("write err: %v", err)
	}
}

func newDownloadMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestGetNetlasDomainsByIP(t *testing.T) {
	fixtureData := readNetlasFixture(t, "ip_download.json")
	ts := setupMockServer(t, fixtureData)
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	netlasRateLimitDelay = 0
	resolver.HTTPTimeout = 2 * time.Second
	resolver.NetlasLimitPerOneDownload = 100

	m := newTestModule(t, testAPIKey)

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities failed: %v", err)
	}
	if _, ok := caps.CustomFunctions[constants.FuncGetNetlasDomainsByIP]; !ok {
		t.Fatalf("expected capability %s to be registered", constants.FuncGetNetlasDomainsByIP)
	}

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeIPv4,
			Value: testIP198,
		},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	exec := out.Executions[0]

	if exec.Error != nil {
		t.Fatalf("execution returned error: %s", *exec.Error)
	}

	domains, records := countDomainsAndRecords(t, exec, testIP198)

	if domains != 5 {
		t.Errorf("expected 5 domains, got %d", domains)
	}
	if records == 0 {
		t.Errorf("expected DNS records to be parsed, got 0")
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestGetNetlasDomainsByDomain(t *testing.T) {
	fixtureData := readNetlasFixture(t, "domain_download.json")
	ts := setupMockServer(t, fixtureData)
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	netlasRateLimitDelay = 0
	resolver.HTTPTimeout = 2 * time.Second
	resolver.NetlasLimitPerOneDownload = 100

	m := newTestModule(t, testAPIKey)

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities failed: %v", err)
	}
	if _, ok := caps.CustomFunctions[constants.FuncGetNetlasDomainsByDomain]; !ok {
		t.Fatalf("expected capability %s to be registered", constants.FuncGetNetlasDomainsByDomain)
	}

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "dl.example.net",
		},
		Functions: []string{constants.FuncGetNetlasDomainsByDomain},
	}

	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	exec := out.Executions[0]

	if exec.Error != nil {
		t.Fatalf("execution returned error: %s", *exec.Error)
	}

	domains, records := countDomainsAndRecords(t, exec, "dl.example.net")

	if domains != 5 {
		t.Errorf("expected 5 domains, got %d", domains)
	}
	if records == 0 {
		t.Errorf("expected DNS records to be parsed, got 0")
	}

	requireUniqueLocalIDs(t, exec.Results)

	execInvalid := m.getNetlasDomainsByQuery(schema.Entity{Type: constants.TypeDomain, Value: "invalid-test.example.org"}, "FuncInvalid", modutil.NewLocalIDGenerator())
	if execInvalid.Function != "FuncInvalid" {
		t.Errorf("expected exec returned immediately, got %v", execInvalid)
	}
}

func countDomainsAndRecords(t *testing.T, exec schema.ModuleExecution, sourceValue string) (domains, records int) {
	for _, res := range exec.Results {
		if slices.Contains(res.Tags, constants.TagPDNS) && (res.Type == constants.TypeDomain || res.Type == constants.TypeSubdomain) {
			domains++
			if res.Source == nil || res.Source.Value != sourceValue {
				t.Errorf("domain %s missing source value. got: %v", res.Value, res.Source)
			}
		}
		if res.Type == constants.TypeIPv4 || res.Type == constants.TypeIPv6 || res.Type == constants.TypeTXT {
			records++
		}
	}
	return domains, records
}

func TestGetNetlasDomainsByIP_Limit0(t *testing.T) {
	resolver.NetlasLimitPerOneDownload = 0
	m := newTestModule(t, testAPIKey)

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities failed: %v", err)
	}
	if _, ok := caps.CustomFunctions[constants.FuncGetNetlasDomainsByIP]; ok {
		t.Fatalf("did not expect capability %s when limit is 0", constants.FuncGetNetlasDomainsByIP)
	}
}

func TestGetNetlasDomainsByIP_DemoMode(t *testing.T) {
	resolver.NetlasLimitPerOneDownload = 100
	netlasRateLimitDelay = 0
	m := newTestModule(t, demoIndicator)

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeIPv4,
			Value: testIP198,
		},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) == 0 {
		t.Fatal("expected at least 1 execution")
	}
	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("Demo mode should not return error, got: %s", *exec.Error)
	}

	domains, _ := countDomainsAndRecords(t, exec, testIP198)
	if domains != 5 {
		t.Errorf("expected 5 domains from demo fixture, got %d", domains)
	}
	if exec.RawData == "" {
		t.Error("expected RawData to be set in demo mode")
	}
}

func TestGetNetlasDomainsByDomain_DemoMode(t *testing.T) {
	resolver.NetlasLimitPerOneDownload = 100
	netlasRateLimitDelay = 0
	m := newTestModule(t, demoIndicator)

	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "demo-target.example.net",
		},
		Functions: []string{constants.FuncGetNetlasDomainsByDomain},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) == 0 {
		t.Fatal("expected at least 1 execution")
	}
	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("Demo mode should not return error, got: %s", *exec.Error)
	}

	if exec.RawData == "" {
		t.Error("expected RawData to be set in demo mode")
	}
}

func TestGetNetlasDomainsByIP_CountZero(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		writeMock(t, w, []byte(`{"count": 0}`))
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	resolver.NetlasLimitPerOneDownload = 100

	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) > 0 && len(out.Executions[0].Results) != 1 {
		t.Fatalf("expected 1 result (target node) when count is 0, got %d", len(out.Executions[0].Results))
	}
}

func TestGetNetlasDomainsByIP_NDJSON(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/domains_count") {
			writeMock(t, w, []byte(`{"count": 2}`))
			return
		}
		writeMock(t, w, []byte("{\"data\": {\"domain\": \"a.example.edu\", \"a\": [\"198.51.100.1\"]}}\n{\"data\": {\"domain\": \"b.example.edu\", \"a\": [\"198.51.100.1\"]}}\n{\"invalid_json: 1}\n{\"data\": {\"domain\": \"invalid domain name!!\"}}\n"))
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	netlasRateLimitDelay = 0
	resolver.NetlasLimitPerOneDownload = 100

	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) == 0 || out.Executions[0].Error != nil {
		t.Fatal("Exec failed with NDJSON")
	}

	var domains int
	for _, res := range out.Executions[0].Results {
		if slices.Contains(res.Tags, constants.TagPDNS) && (res.Type == constants.TypeDomain || res.Type == constants.TypeSubdomain) {
			domains++
		}
	}
	if domains != 2 {
		t.Fatalf("expected 2 domains, got %d", domains)
	}
}

func TestGetNetlasDomainsByIP_CountError(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	resolver.NetlasLimitPerOneDownload = 100
	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	hasInfoNode := false
	if len(out.Executions) > 0 {
		for _, res := range out.Executions[0].Results {
			if res.Type == constants.TypeInfo {
				hasInfoNode = true
			}
		}
	}
	if !hasInfoNode {
		t.Fatal("expected info node on count error")
	}
}

func TestGetNetlasDomainsByIP_CountJSONError(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		writeMock(t, w, []byte(`invalid json`))
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	resolver.NetlasLimitPerOneDownload = 100
	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) > 0 && out.Executions[0].Error == nil {
		t.Fatal("expected error on count JSON parse fail")
	}
}

func TestGetNetlasDomainsByIP_DownloadError(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/domains_count") {
			writeMock(t, w, []byte(`{"count": 2}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	resolver.NetlasLimitPerOneDownload = 100
	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	hasInfoNode := false
	if len(out.Executions) > 0 {
		for _, res := range out.Executions[0].Results {
			if res.Type == constants.TypeInfo {
				hasInfoNode = true
			}
		}
	}
	if !hasInfoNode {
		t.Fatal("expected info node on download error")
	}
}

func TestGetNetlasDomainsByIP_DownloadJSONError(t *testing.T) {
	ts := newDownloadMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/users/current") {
			writeMock(t, w, []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/domains_count") {
			writeMock(t, w, []byte(`{"count": 2}`))
			return
		}
		writeMock(t, w, []byte(`[invalid`))
	})
	defer ts.Close()

	netlasAPIBaseURL = ts.URL
	resolver.NetlasLimitPerOneDownload = 100
	m := newTestModule(t, testAPIKey)

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
		Functions: []string{constants.FuncGetNetlasDomainsByIP},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}
	if len(out.Executions) > 0 && out.Executions[0].Error == nil {
		t.Fatal("expected error on download JSON parse fail")
	}
}

func TestFetchDomainCountNetworkError(t *testing.T) {
	tsClosed := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	tsClosed.Close()
	netlasAPIBaseURL = tsClosed.URL

	m := newTestModule(t, testAPIKey)
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetNetlasDomainsByIP}

	_, ok := m.fetchDomainCount(exec, "a:198.51.100.1", "198.51.100.1", gen)
	if ok {
		t.Fatal("expected fetchDomainCount to fail on network error")
	}
}

func TestDownloadAndParseNetworkError(t *testing.T) {
	tsClosed := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	tsClosed.Close()
	netlasAPIBaseURL = tsClosed.URL

	m := newTestModule(t, testAPIKey)
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetNetlasDomainsByIP}

	_, ok := m.downloadAndParse(exec, []byte(`{"q":"a:198.51.100.1","size":10}`), "198.51.100.1", gen)
	if ok {
		t.Fatal("expected downloadAndParse to fail on network error")
	}
}

func TestResolveDownloadSize(t *testing.T) {
	m := newTestModule(t, testAPIKey)

	originalLimit := resolver.NetlasLimitPerOneDownload
	defer func() { resolver.NetlasLimitPerOneDownload = originalLimit }()

	resolver.NetlasLimitPerOneDownload = 50
	m.mu.Lock()
	m.limitPerDl = 1000
	m.mu.Unlock()
	if got := m.resolveDownloadSize(200); got != 50 {
		t.Errorf("expected user limit 50 to cap size, got %d", got)
	}

	resolver.NetlasLimitPerOneDownload = 500
	m.mu.Lock()
	m.limitPerDl = 30
	m.mu.Unlock()
	if got := m.resolveDownloadSize(200); got != 30 {
		t.Errorf("expected plan limit 30 to cap size, got %d", got)
	}

	resolver.NetlasLimitPerOneDownload = 100
	m.mu.Lock()
	m.limitPerDl = 20
	m.mu.Unlock()
	if got := m.resolveDownloadSize(200); got != 20 {
		t.Errorf("expected plan limit 20 to cap after user limit, got %d", got)
	}
}

func TestEmitDomainResultsEmptyDomain(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetNetlasDomainsByIP}
	targetRef := &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.1"}

	items := []downloadItem{
		{Data: struct {
			Domain string `json:"domain"`
			netlasDNS
		}{Domain: ""}},
		{Data: struct {
			Domain string `json:"domain"`
			netlasDNS
		}{Domain: "valid-domain.example.org"}},
	}

	emitDomainResults(exec, items, targetRef, gen)

	var domains int
	for _, res := range exec.Results {
		if slices.Contains(res.Tags, constants.TagPDNS) {
			domains++
		}
	}
	if domains != 1 {
		t.Errorf("expected 1 domain (empty should be skipped), got %d", domains)
	}
}

func TestExecuteHTTPPostRequest_ReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	netlasAPIBaseURL = ts.URL

	m := newTestModule(t, testAPIKey)
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetNetlasDomainsByIP}

	_, _, _, reqOK := m.executeHTTPPostRequest(exec, ts.URL, nil, 0, "198.51.100.1", gen)
	if reqOK {
		t.Fatal("expected reqOK=false on truncated body")
	}
}
