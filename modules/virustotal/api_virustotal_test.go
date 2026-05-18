package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	fixtureDomainTarget  = "target-example.com"
	fixtureIPTarget      = "192.0.2.44"
	fixtureAPISubdomain  = "api.target-example.com"
	fixtureVPNSubdomain  = "vpn.target-example.com"
	fixtureMailSubdomain = "mail.target-example.com"
	fixtureFixtureAPIKey = "fixture-key"
)

type vtMockRequest struct {
	at     time.Time
	path   string
	apiKey string
}

type vtMockServer struct {
	responses map[string]string
	statuses  map[string]int
	requests  []vtMockRequest
	mu        sync.Mutex
}

func newVTMockServer(t *testing.T, responses map[string]string, statuses map[string]int) (*vtMockServer, *httptest.Server) {
	t.Helper()

	mock := &vtMockServer{
		responses: responses,
		statuses:  statuses,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}

		mock.mu.Lock()
		mock.requests = append(mock.requests, vtMockRequest{
			at:     time.Now(),
			path:   path,
			apiKey: r.Header.Get("x-apikey"),
		})
		mock.mu.Unlock()

		if status, ok := mock.statuses[path]; ok {
			w.WriteHeader(status)
			return
		}

		body, ok := mock.responses[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body = strings.ReplaceAll(body, "SERVER_URL", serverURL(r))

		var payload any
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			return
		}
	}))

	return mock, server
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func (m *vtMockServer) allRequests() []vtMockRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	requests := make([]vtMockRequest, len(m.requests))
	copy(requests, m.requests)
	return requests
}

func (m *vtMockServer) requestsForPath(path string) []vtMockRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	requests := make([]vtMockRequest, 0, len(m.requests))
	for _, req := range m.requests {
		if req.path == path {
			requests = append(requests, req)
		}
	}
	return requests
}

func loadVTFixture(t *testing.T, fileName string) string {
	t.Helper()

	var (
		data []byte
		err  error
	)

	switch fileName {
	case "domain_page1.json":
		data, err = os.ReadFile("testdata/domain_page1.json")
	case "subdomains_page1.json":
		data, err = os.ReadFile("testdata/subdomains_page1.json")
	case "subdomains_page2.json":
		data, err = os.ReadFile("testdata/subdomains_page2.json")
	case "ip_page1.json":
		data, err = os.ReadFile("testdata/ip_page1.json")
	case "resolutions_page1.json":
		data, err = os.ReadFile("testdata/resolutions_page1.json")
	case "resolutions_page2.json":
		data, err = os.ReadFile("testdata/resolutions_page2.json")
	default:
		t.Fatalf("unsupported fixture %s", fileName)
	}
	if err != nil {
		t.Fatalf("read fixture %s: %v", fileName, err)
	}

	return string(data)
}

func setVTBaseURL(t *testing.T, url string) {
	t.Helper()

	original := baseURL
	baseURL = url
	t.Cleanup(func() {
		baseURL = original
	})
}

func execVT(t *testing.T, mod *module, target schema.Entity) schema.ModuleExecution {
	t.Helper()

	fn := constants.FuncGetVTApiDomain
	if target.Type == constants.TypeIPv4 || target.Type == constants.TypeIPv6 {
		fn = constants.FuncGetVTApiIP
	}

	output, err := mod.Exec(schema.ModuleInput{
		Target:    target,
		Functions: []string{fn},
	})
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	return output.Executions[0]
}

func requireResult(t *testing.T, results []schema.ModuleResult, description string, predicate func(schema.ModuleResult) bool) *schema.ModuleResult {
	t.Helper()

	for i := range results {
		if predicate(results[i]) {
			return &results[i]
		}
	}

	t.Fatalf("expected result: %s", description)
	return nil
}

func assertNoResult(t *testing.T, results []schema.ModuleResult, description string, predicate func(schema.ModuleResult) bool) {
	t.Helper()

	for _, result := range results {
		if predicate(result) {
			t.Fatalf("unexpected result for %s: %+v", description, result)
		}
	}
}

func resultTextContains(result *schema.ModuleResult, parts ...string) bool {
	text := result.Type + "\n" + result.Value + "\n" + result.Context
	for _, part := range parts {
		if !strings.Contains(text, part) {
			return false
		}
	}
	return true
}

func assertSinglePathHit(t *testing.T, mock *vtMockServer, path string) vtMockRequest {
	t.Helper()

	hits := mock.requestsForPath(path)
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 hit for %s, got %d", path, len(hits))
	}
	return hits[0]
}

func assertRequestAPIKey(t *testing.T, requests []vtMockRequest, apiKey string) {
	t.Helper()

	for _, req := range requests {
		if req.apiKey != apiKey {
			t.Fatalf("expected x-apikey %q for %s, got %q", apiKey, req.path, req.apiKey)
		}
	}
}

func assertMinimumGap(t *testing.T, earlier, later vtMockRequest, label string) {
	t.Helper()

	const minGap = 5 * time.Millisecond
	if gap := later.at.Sub(earlier.at); gap < minGap {
		t.Fatalf("expected %s gap >= %s, got %s", label, minGap, gap)
	}
}

func assertTagResult(t *testing.T, results []schema.ModuleResult, expectedTag string) {
	t.Helper()

	tagResult := requireResult(t, results, "tag "+expectedTag, func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeTag && result.Value == expectedTag
	})
	if tagResult.Category != constants.CategoryProperty {
		t.Fatalf("expected tag to be property, got %+v", tagResult)
	}
}

func TestModuleCapabilities(t *testing.T) {
	mod := &module{apiKey: ""}
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities error: %v", err)
	}
	if len(caps.CustomFunctions) != 0 {
		t.Fatalf("expected empty custom functions without key, got %+v", caps.CustomFunctions)
	}

	mod.apiKey = "valid-key"
	caps, err = mod.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities error: %v", err)
	}

	fnCaps, ok := caps.CustomFunctions[constants.FuncGetVTApiDomain]
	if !ok {
		t.Fatalf("expected %s in custom functions", constants.FuncGetVTApiDomain)
	}

	ipCaps, ok := caps.CustomFunctions[constants.FuncGetVTApiIP]
	if !ok {
		t.Fatalf("expected %s in custom functions", constants.FuncGetVTApiIP)
	}
	if caps.ModuleConfig == nil || caps.ModuleConfig.Limit != 1 {
		t.Fatalf("expected ModuleConfig limit 1, got %+v", caps.ModuleConfig)
	}
	if len(fnCaps.InputTypes) == 0 || len(ipCaps.InputTypes) == 0 {
		t.Fatalf("expected input types on functions")
	}
}

func TestNewUsesAPIConfigEnvOverride(t *testing.T) {
	t.Setenv("RECONSR_VIRUSTOTAL", "env-key")

	mod, ok := New().(*module)
	if !ok {
		t.Fatal("expected New to return *module")
	}
	if mod.apiKey != "env-key" {
		t.Fatalf("expected env api key, got %q", mod.apiKey)
	}
}

func TestDoVTRequestClassifiesRateLimit(t *testing.T) {
	statuses := map[string]int{
		"/api/v3/domains/" + fixtureDomainTarget: http.StatusTooManyRequests,
	}
	_, server := newVTMockServer(t, nil, statuses)
	defer server.Close()

	originalDelay := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = originalDelay }()

	mod := &module{apiKey: fixtureFixtureAPIKey}
	_, _, err := mod.doVTRequest(context.Background(), server.URL+"/api/v3/domains/"+fixtureDomainTarget)
	if err == nil {
		t.Fatal("expected rate-limit error")
	}
	if action := requestAction(err); action != httputil.RateLimit {
		t.Fatalf("expected RateLimit action, got %d", action)
	}
	if mod.keyInvalid.Load() {
		t.Fatal("did not expect keyInvalid after 429")
	}
}

func TestModuleKeyInvalidationStopsFurtherRequests(t *testing.T) {
	statuses := map[string]int{
		"/api/v3/domains/fail-example.com": http.StatusUnauthorized,
	}
	mock, server := newVTMockServer(t, nil, statuses)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: "invalid-key"}
	first := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "fail-example.com"})
	if first.Error == nil {
		t.Fatal("expected first execution to fail with 401")
	}
	if !mod.keyInvalid.Load() {
		t.Fatal("expected keyInvalid to be set after 401")
	}

	second := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "fail-example.com"})
	if second.Error != nil {
		t.Fatalf("expected second execution to stop gracefully, got error %q", *second.Error)
	}

	info := requireResult(t, second.Results, "info result after key invalidation", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeInfo && strings.Contains(result.Value, "API key invalid")
	})
	if info.Category != constants.CategoryProperty {
		t.Fatalf("expected info result to be property, got %q", info.Category)
	}

	requests := mock.allRequests()
	if len(requests) != 1 {
		t.Fatalf("expected exactly one upstream request after invalidation, got %d", len(requests))
	}
	assertRequestAPIKey(t, requests, "invalid-key")
}

func TestModuleKeyInvalidationAlsoHandlesForbidden(t *testing.T) {
	statuses := map[string]int{
		"/api/v3/domains/forbidden-example.com": http.StatusForbidden,
	}
	mock, server := newVTMockServer(t, nil, statuses)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: "forbidden-key"}
	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "forbidden-example.com"})
	if exec.Error == nil || !strings.Contains(*exec.Error, "HTTP 403") {
		t.Fatalf("expected HTTP 403 execution error, got %+v", exec.Error)
	}
	if !mod.keyInvalid.Load() {
		t.Fatal("expected keyInvalid to be set after 403")
	}

	requests := mock.allRequests()
	if len(requests) != 1 {
		t.Fatalf("expected exactly one upstream request, got %d", len(requests))
	}
	assertRequestAPIKey(t, requests, "forbidden-key")
}

func TestMockFixtureLoader(t *testing.T) {
	for _, fileName := range []string{
		"domain_page1.json",
		"subdomains_page1.json",
		"subdomains_page2.json",
		"ip_page1.json",
		"resolutions_page1.json",
		"resolutions_page2.json",
	} {
		if data := loadVTFixture(t, fileName); strings.TrimSpace(data) == "" {
			t.Fatalf("fixture %s is empty", fileName)
		}
	}
}

func describeSource(source *schema.EntityRef) string {
	if source == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s:%s", source.Type, source.Value)
}

func TestProcessPaginatedLimits(t *testing.T) {
	domainBody := loadVTFixture(t, "domain_page1.json")
	subdomainsPage1 := loadVTFixture(t, "subdomains_page1.json")
	subdomainsPage2 := loadVTFixture(t, "subdomains_page2.json")

	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = 15000 }()

	responses := map[string]string{
		"/api/v3/domains/" + fixtureDomainTarget:                                                                    domainBody,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40":                                           subdomainsPage1,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2": subdomainsPage2,
	}

	mock, server := newVTMockServer(t, responses, nil)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	originalMaxPages := resolver.VirustotalMaxPages
	resolver.VirustotalMaxPages = 1
	defer func() { resolver.VirustotalMaxPages = originalMaxPages }()

	mod := &module{apiKey: fixtureFixtureAPIKey}
	execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})

	requests := mock.requestsForPath("/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2")
	if len(requests) > 0 {
		t.Fatalf("expected 0 requests to page 2 due to VirustotalMaxPages=1 limit, got %d", len(requests))
	}
}
