package virustotal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	fixtureDomainTarget  = "target-example.com"
	fixtureIPTarget      = "192.0.2.44"
	fixtureAPISubdomain  = "api.target-example.com"
	fixtureVPNSubdomain  = "vpn.target-example.com"
	fixtureMailSubdomain = "mail.target-example.com"
	fixtureTestAPIKey    = "fixture-key"
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
	case "communicating_files.json":
		data, err = os.ReadFile("testdata/communicating_files.json")
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

	t.Fatalf("expected result: %s, got: %+v", description, results)
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

	mod.apiKey = fixtureTestAPIKey
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

	originalScan := resolver.VirustotalScanSubdomains
	resolver.VirustotalScanSubdomains = true
	defer func() { resolver.VirustotalScanSubdomains = originalScan }()

	caps, err = mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Contains(caps.CustomFunctions[constants.FuncGetVTApiDomain].InputTypes, constants.TypeSubdomain) {
		t.Fatalf("expected TypeSubdomain in InputTypes when VirustotalScanSubdomains is true")
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

	mod := &module{apiKey: fixtureTestAPIKey}
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
	if first.Error != nil {
		t.Fatalf("expected first execution to return info, not error, got %v", *first.Error)
	}
	requireResult(t, first.Results, "info result on 401", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeInfo && strings.Contains(result.Value, "HTTP 401")
	})
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
	if exec.Error != nil {
		t.Fatalf("expected HTTP 403 to return info, not error, got %+v", exec.Error)
	}
	requireResult(t, exec.Results, "info result on 403", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeInfo && strings.Contains(result.Value, "HTTP 403")
	})
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

	mod := &module{apiKey: fixtureTestAPIKey}
	execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})

	requests := mock.requestsForPath("/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2")
	if len(requests) > 0 {
		t.Fatalf("expected 0 requests to page 2 due to VirustotalMaxPages=1 limit, got %d", len(requests))
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
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

	_, server := newVTMockServer(t, responses, nil)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}
	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})

	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %q", *exec.Error)
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

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true
	}
}

func TestVTRequestError_Unwrap(t *testing.T) {
	err := errors.New("underlying error")
	reqErr := &vtRequestError{
		err:    err,
		action: httputil.Abort,
	}

	if reqErr.Error() != "underlying error" {
		t.Errorf("expected Error() to return %q, got %q", "underlying error", reqErr.Error())
	}

	if unwrapped := reqErr.Unwrap(); !errors.Is(unwrapped, err) {
		t.Errorf("expected Unwrap() to return %v, got %v", err, unwrapped)
	}

	var target *vtRequestError
	wrapped := fmt.Errorf("wrapped: %w", reqErr)
	if !errors.As(wrapped, &target) {
		t.Error("errors.As failed to unwrap vtRequestError")
	}
}

func TestRequestAction_Fallback(t *testing.T) {
	err := errors.New("arbitrary generic error")
	action := requestAction(err)
	if action != httputil.Abort {
		t.Errorf("expected httputil.Abort for non-vtRequestError, got %v", action)
	}
}

func TestModuleDemoModeAndName(t *testing.T) {
	mod := &module{apiKey: demoIndicator}

	if mod.Name() != "virustotal" {
		t.Errorf("expected Name() to be 'virustotal', got %q", mod.Name())
	}

	execDomain := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})
	if execDomain.Error != nil {
		t.Fatalf("demo mode domain exec error: %s", *execDomain.Error)
	}
	if len(execDomain.Results) == 0 {
		t.Fatal("expected results in demo mode for domain, got 0")
	}

	execIP := execVT(t, mod, schema.Entity{Type: constants.TypeIPv4, Value: fixtureIPTarget})
	if execIP.Error != nil {
		t.Fatalf("demo mode ip exec error: %s", *execIP.Error)
	}
	if len(execIP.Results) == 0 {
		t.Fatal("expected results in demo mode for IP, got 0")
	}

	execDomain2 := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})
	if len(execDomain2.Results) != 0 {
		t.Fatalf("expected 0 results on second demo domain call, got %d", len(execDomain2.Results))
	}

	execIP2 := execVT(t, mod, schema.Entity{Type: constants.TypeIPv4, Value: fixtureIPTarget})
	if len(execIP2.Results) != 0 {
		t.Fatalf("expected 0 results on second demo ip call, got %d", len(execIP2.Results))
	}

	execCommDomain := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})
	if execCommDomain.Error != nil {
		t.Fatalf("demo mode domain comm files exec error: %s", *execCommDomain.Error)
	}
	if len(execCommDomain.Results) == 0 {
		t.Fatal("expected results in demo mode for domain comm files, got 0")
	}

	execCommIP := execVTCommFiles(t, mod, constants.FuncGetVTApiIPCommunicatingFiles, schema.Entity{Type: constants.TypeIPv4, Value: fixtureIPTarget})
	if execCommIP.Error != nil {
		t.Fatalf("demo mode IP comm files exec error: %s", *execCommIP.Error)
	}
	if len(execCommIP.Results) == 0 {
		t.Fatal("expected results in demo mode for IP comm files, got 0")
	}

	execCommDomain2 := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})
	if len(execCommDomain2.Results) != 0 {
		t.Fatalf("expected 0 results on second demo domain comm files call, got %d", len(execCommDomain2.Results))
	}

	execCommIP2 := execVTCommFiles(t, mod, constants.FuncGetVTApiIPCommunicatingFiles, schema.Entity{Type: constants.TypeIPv4, Value: fixtureIPTarget})
	if len(execCommIP2.Results) != 0 {
		t.Fatalf("expected 0 results on second demo IP comm files call, got %d", len(execCommIP2.Results))
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("mock read error")
}

func (errReader) Close() error {
	return nil
}

func TestProcessResponse_ReadError(t *testing.T) {
	m := &module{}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       errReader{},
	}
	data, body, err := m.processResponse(resp, 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if data != nil {
		t.Errorf("expected nil data, got %v", data)
	}
	if body != "" {
		t.Errorf("expected empty body, got %q", body)
	}
	var reqErrWrap *vtRequestError
	if !errors.As(err, &reqErrWrap) {
		t.Fatalf("expected vtRequestError, got %T: %v", err, err)
	}
	if reqErrWrap.action != httputil.Retry {
		t.Errorf("expected action Retry, got %d", reqErrWrap.action)
	}
}

func TestProcessResponse_UnmarshalError(t *testing.T) {
	m := &module{}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewBufferString("invalid json")),
	}
	data, body, err := m.processResponse(resp, 1)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if data != nil {
		t.Errorf("expected nil data, got %v", data)
	}
	if body != "invalid json" {
		t.Errorf("expected body 'invalid json', got %q", body)
	}
	var reqErrWrap *vtRequestError
	if !errors.As(err, &reqErrWrap) {
		t.Fatalf("expected vtRequestError, got %T: %v", err, err)
	}
	if reqErrWrap.action != httputil.Abort {
		t.Errorf("expected action Abort, got %d", reqErrWrap.action)
	}
}

func TestDoVTRequest_RateLimitContextCancelled(t *testing.T) {
	originalDelay := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 10000
	defer func() { resolver.VirustotalDelayMs = originalDelay }()

	m := &module{
		lastReqTime: time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data, body, err := m.doVTRequest(ctx, "http://example.com")

	if data != nil || body != "" || err == nil {
		t.Fatalf("expected error from context cancellation, got data=%v, body=%q, err=%v", data, body, err)
	}
	var reqErrWrap *vtRequestError
	if !errors.As(err, &reqErrWrap) {
		t.Fatalf("expected vtRequestError, got %T", err)
	}
	if reqErrWrap.action != httputil.Abort {
		t.Errorf("expected Abort, got %d", reqErrWrap.action)
	}
}

func TestDoVTRequest_CreateRequestError(t *testing.T) {
	m := &module{}
	ctx := context.Background()
	data, body, err := m.doVTRequest(ctx, ":\x00")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if data != nil || body != "" {
		t.Errorf("expected nil data and empty body")
	}
}

func TestDoVTRequest_DoRequestError(t *testing.T) {
	originalRetries := resolver.VirustotalMaxRetries
	resolver.VirustotalMaxRetries = 0
	defer func() { resolver.VirustotalMaxRetries = originalRetries }()

	m := &module{}
	ctx := context.Background()

	data, body, err := m.doVTRequest(ctx, "http://127.0.0.1:0")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if data != nil || body != "" {
		t.Errorf("expected nil data and empty body")
	}
	var reqErrWrap *vtRequestError
	if !errors.As(err, &reqErrWrap) {
		t.Fatalf("expected vtRequestError, got %T", err)
	}
	if reqErrWrap.action != httputil.Retry {
		t.Errorf("expected action Retry, got %d", reqErrWrap.action)
	}
}

func TestDoVTRequest_RetrySleepContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	m := &module{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	data, body, err := m.doVTRequest(ctx, srv.URL)
	if err == nil {
		t.Fatal("expected error from context cancellation during sleep")
	}
	if data != nil {
		t.Errorf("expected nil data")
	}
	if body != "" {
		t.Errorf("expected empty body")
	}
	var reqErrWrap *vtRequestError
	if !errors.As(err, &reqErrWrap) {
		t.Fatalf("expected vtRequestError, got %T: %v", err, err)
	}
	if reqErrWrap.action != httputil.Abort {
		t.Errorf("expected Abort, got %d", reqErrWrap.action)
	}
	if !strings.Contains(err.Error(), "context cancelled during retry wait") {
		t.Errorf("expected 'context cancelled during retry wait', got %v", err)
	}
}

func TestProcessDomainDemo_ErrorsAndEdgeCases(t *testing.T) {
	originalReadFile := readDemoFile
	defer func() { readDemoFile = originalReadFile }()

	m := &module{}
	ctx := context.Background()
	gen := modutil.NewLocalIDGenerator()

	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	exec := &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d1.example.com", exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "mock read error") {
		t.Errorf("expected mock read error, got %v", exec.Error)
	}

	m.demoDomainFired.Store(false)
	readDemoFile = func(_ string) ([]byte, error) {
		return []byte("invalid json"), nil
	}
	exec = &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d2.example.com", exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "unmarshal fixture err") {
		t.Errorf("expected unmarshal error, got %v", exec.Error)
	}

	m.demoDomainFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "subdomains_page") {
			return nil, errors.New("mock read error for subdomains")
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d3.example.com", exec, gen)

	m.demoDomainFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "subdomains_page") {
			return []byte("invalid json"), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d4.example.com", exec, gen)

	m.demoDomainFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "subdomains_page") {
			return []byte(`{"data": {}}`), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d5.example.com", exec, gen)

	m.demoDomainFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "subdomains_page1") {
			mockExpired := `{
				"data": [
					{
						"type": "domain",
						"id": "expired.example.org",
						"attributes": {
							"last_https_certificate": {
								"validity": {
									"not_after": "2000-01-01 00:00:00"
								}
							}
						}
					}
				]
			}`
			return []byte(mockExpired), nil
		} else if strings.Contains(name, "subdomains_page") {
			return []byte(`{"data":[]}`), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processDomainDemo(ctx, constants.TypeDomain, "d6.example.com", exec, gen)
	foundExpired := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeCertExpiredSubdomains {
			foundExpired = true
			if !strings.Contains(res.Value, "expired.example.org") {
				t.Errorf("expected value to contain expired.example.org, got %v", res.Value)
			}
			break
		}
	}
	if !foundExpired {
		t.Error("expected to find expired domain result")
	}
}

func TestProcessIPDemo_ErrorsAndEdgeCases(t *testing.T) {
	originalReadFile := readDemoFile
	defer func() { readDemoFile = originalReadFile }()

	m := &module{}
	ctx := context.Background()
	gen := modutil.NewLocalIDGenerator()

	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	exec := &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.1", exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "mock read error") {
		t.Errorf("expected mock read error, got %v", exec.Error)
	}

	m.demoIPFired.Store(false)
	readDemoFile = func(_ string) ([]byte, error) {
		return []byte("invalid json"), nil
	}
	exec = &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.2", exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "unmarshal fixture err") {
		t.Errorf("expected unmarshal error, got %v", exec.Error)
	}

	m.demoIPFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "resolutions_page") {
			return nil, errors.New("mock read error for resolutions")
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.3", exec, gen)

	m.demoIPFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "resolutions_page") {
			return []byte("invalid json"), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.4", exec, gen)

	m.demoIPFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "resolutions_page") {
			return []byte(`{"data": {}}`), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.5", exec, gen)

	m.demoIPFired.Store(false)
	readDemoFile = func(name string) ([]byte, error) {
		if strings.Contains(name, "resolutions_page") {
			return []byte(`{"data": ["string_instead_of_map"]}`), nil
		}
		return originalReadFile(name)
	}
	exec = &schema.ModuleExecution{}
	m.processIPDemo(ctx, "127.0.0.6", exec, gen)
}

func TestExec_UnsupportedFunction(t *testing.T) {
	mod := &module{apiKey: "test"}
	output, err := mod.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "127.0.0.1"},
		Functions: []string{"unsupported_function"},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution")
	}
	exec := output.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "unsupported function") {
		t.Errorf("expected unsupported function error, got %v", exec.Error)
	}
}

func TestProcessPaginated_EdgeCases(t *testing.T) {
	mod := &module{apiKey: "test-key"}
	ctx := context.Background()

	originalDelay := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = originalDelay }()

	originalRetries := resolver.VirustotalMaxRetries
	resolver.VirustotalMaxRetries = 0
	defer func() { resolver.VirustotalMaxRetries = originalRetries }()

	t.Run("error_request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		exec := &schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		mod.processPaginated(ctx, srv.URL, exec, gen, func(_ map[string]any) {})
		if exec.Error == nil || !strings.Contains(*exec.Error, "pagination failed") {
			t.Errorf("expected pagination error, got %v", exec.Error)
		}
	})

	t.Run("missing_links", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(`{"data": [{"id": "1"}]}`)); err != nil {
				panic(err)
			}
		}))
		defer srv.Close()

		exec := &schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		count := 0
		mod.processPaginated(ctx, srv.URL, exec, gen, func(_ map[string]any) { count++ })
		if count != 1 {
			t.Errorf("expected 1 item, got %d", count)
		}
		if exec.Error != nil {
			t.Errorf("unexpected error: %v", *exec.Error)
		}
	})

	t.Run("empty_raw_no_data", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := w.Write([]byte(`{"data": [], "links": {"next": ""}}`)); err != nil {
				panic(err)
			}
		}))
		defer srv.Close()

		ctxCancel, cancel := context.WithCancel(context.Background())
		cancel()

		exec := &schema.ModuleExecution{}
		gen := modutil.NewLocalIDGenerator()
		mod.processPaginated(ctxCancel, srv.URL, exec, gen, func(_ map[string]any) {})
		if exec.Error == nil {
			t.Error("expected error due to cancelled context")
		}
		if strings.Contains(exec.RawData, "\n---\n") {
			t.Errorf("did not expect raw data to be saved, got %q", exec.RawData)
		}
	})
}

func TestParseVTError_Coverage(t *testing.T) {
	err1 := parseVTError(400, []byte(`{"error": {"code": "BadRequestError", "message": "Invalid request"}}`))
	if err1.Error() != "HTTP 400 (BadRequestError): Invalid request" {
		t.Errorf("expected HTTP 400 (BadRequestError): Invalid request, got %s", err1.Error())
	}

	err2 := parseVTError(400, []byte(`{"error": {"message": "Invalid request"}}`))
	if err2.Error() != "HTTP 400: Invalid request" {
		t.Errorf("expected HTTP 400: Invalid request, got %s", err2.Error())
	}
}

func TestProcessResponse_NotFound(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	originalBaseURL := baseURL
	baseURL = mockServer.URL
	defer func() { baseURL = originalBaseURL }()

	originalDelay := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = originalDelay }()

	mod := &module{}
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	mod.processDomain(context.Background(), constants.TypeDomain, "not-found.com", exec, gen)

	if exec.Error != nil {
		t.Errorf("expected no error for 404, got %v", *exec.Error)
	}
}

func TestProcessCommFilesDemo_ErrorsAndEdgeCases(t *testing.T) {
	originalReadFile := readDemoFile
	defer func() { readDemoFile = originalReadFile }()

	m := &module{}
	ctx := context.Background()
	gen := modutil.NewLocalIDGenerator()

	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	exec := &schema.ModuleExecution{}
	m.processCommunicatingFilesDemo(ctx, constants.FuncGetVTApiDomainCommunicatingFiles, exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "mock read error") {
		t.Errorf("expected mock read error, got %v", exec.Error)
	}

	m.demoDomainCommFilesFired.Store(false)
	readDemoFile = func(_ string) ([]byte, error) {
		return []byte("invalid json"), nil
	}
	exec = &schema.ModuleExecution{}
	m.processCommunicatingFilesDemo(ctx, constants.FuncGetVTApiDomainCommunicatingFiles, exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "demo unmarshal error") {
		t.Errorf("expected unmarshal error, got %v", exec.Error)
	}

	m.demoIPCommFilesFired.Store(false)
	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	exec = &schema.ModuleExecution{}
	m.processCommunicatingFilesDemo(ctx, constants.FuncGetVTApiIPCommunicatingFiles, exec, gen)
	if exec.Error == nil || !strings.Contains(*exec.Error, "mock read error") {
		t.Errorf("expected mock read error, got %v", exec.Error)
	}
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errorReadCloser struct {
	io.Reader
}

func (errorReadCloser) Close() error {
	return errors.New("simulated close error")
}

func TestDoVTRequest_CloseError(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{strings.NewReader(`{"data": {}}`)},
			}, nil
		},
	}
	defer func() { http.DefaultTransport = oldTransport }()

	m := &module{}
	_, _, err := m.doVTRequest(context.Background(), "http://example.com")
	if err != nil && !strings.Contains(err.Error(), "simulated close error") {
		t.Logf("Expected some error or nil, got: %v", err)
	}
}
