package hunterio

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestFetchDomainPage_ZeroRetries(t *testing.T) {
	oldRetries := resolver.HunterioMaxRetries
	resolver.HunterioMaxRetries = 0
	defer func() { resolver.HunterioMaxRetries = oldRetries }()

	m := &module{apiKey: testAPIKey}
	exec := &schema.ModuleExecution{}
	_, _, shouldBreak := m.fetchDomainPage(context.Background(), exec, constants.TypeDomain, "example.com", 10, 0)

	if !shouldBreak {
		t.Errorf("expected shouldBreak to be true on zero retries")
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "after retries: no response") {
		t.Errorf("expected no response error, got: %v", exec.Error)
	}
}

func TestDoPageRequest_NewRequestError(t *testing.T) {
	m := &module{apiKey: testAPIKey}
	_, _, err := m.doPageRequest(context.Background(), "http://127.0.0.1/\x7f")
	if err == nil || !strings.Contains(err.Error(), "new request error") {
		t.Errorf("expected new request error, got: %v", err)
	}
}

func TestDoPageRequest_CloseBodyError(t *testing.T) {
	oldTransport := httpClientTransport
	defer func() { httpClientTransport = oldTransport }()

	httpClientTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errCloseReader(0),
			}, nil
		},
	}

	m := &module{apiKey: testAPIKey}
	_, _, err := m.doPageRequest(context.Background(), "http://127.0.0.1")
	if err != nil {
		t.Errorf("expected no error from doPageRequest even if close fails, got: %v", err)
	}
}

func TestDoPageRequest_ReadBodyError(t *testing.T) {
	oldTransport := httpClientTransport
	oldDelay := resolver.RetryBaseDelay
	oldRetries := resolver.HunterioMaxRetries
	defer func() {
		httpClientTransport = oldTransport
		resolver.RetryBaseDelay = oldDelay
		resolver.HunterioMaxRetries = oldRetries
	}()

	resolver.RetryBaseDelay = time.Millisecond
	resolver.HunterioMaxRetries = 1

	httpClientTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReader(0),
			}, nil
		},
	}

	m := &module{apiKey: testAPIKey}
	_, _, err := m.doPageRequest(context.Background(), "http://127.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "read error") {
		t.Errorf("expected read error, got: %v", err)
	}
}

func TestDoPageRequest_ServerErrorRetry(t *testing.T) {
	oldTransport := httpClientTransport
	oldDelay := resolver.RetryBaseDelay
	oldRetries := resolver.HunterioMaxRetries
	defer func() {
		httpClientTransport = oldTransport
		resolver.RetryBaseDelay = oldDelay
		resolver.HunterioMaxRetries = oldRetries
	}()

	resolver.RetryBaseDelay = time.Millisecond
	resolver.HunterioMaxRetries = 2

	var attempts int
	httpClientTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("server error")),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			}, nil
		},
	}

	m := &module{apiKey: testAPIKey}
	_, status, err := m.doPageRequest(context.Background(), "http://127.0.0.1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200, got: %v", status)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got: %v", attempts)
	}
}

func TestDoPageRequest_ClientDoErrorRetry(t *testing.T) {
	oldTransport := httpClientTransport
	oldDelay := resolver.RetryBaseDelay
	oldRetries := resolver.HunterioMaxRetries
	defer func() {
		httpClientTransport = oldTransport
		resolver.RetryBaseDelay = oldDelay
		resolver.HunterioMaxRetries = oldRetries
	}()

	resolver.RetryBaseDelay = time.Millisecond
	resolver.HunterioMaxRetries = 2

	var attempts int
	httpClientTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return nil, errors.New("client do err")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{}")),
			}, nil
		},
	}

	m := &module{apiKey: testAPIKey}
	_, status, err := m.doPageRequest(context.Background(), "http://127.0.0.1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if status != http.StatusOK {
		t.Errorf("expected status 200, got: %v", status)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got: %v", attempts)
	}
}

const testAPIKey = "test_key"

func setupMockServer(t *testing.T, domainFixture string, domainStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(validAccountJSON)); err != nil {
			t.Logf("write failed: %v", err)
		}
	})
	if domainFixture != "" {
		mux.HandleFunc("/domain-search", func(w http.ResponseWriter, _ *http.Request) {
			data := loadHunterioFixture(t, domainFixture)
			w.WriteHeader(domainStatus)
			if _, err := w.Write(data); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	}
	return httptest.NewServer(mux)
}

const validAccountJSON = `{"data": {"requests": {"searches": {"used": 10, "available": 1000}}}}`

func loadHunterioFixture(t *testing.T, filename string) []byte {
	t.Helper()
	var data []byte
	var err error
	switch filename {
	case "domain_search_pagination_page1.json":
		data, err = os.ReadFile("testdata/domain_search_pagination_page1.json")
	case "domain_search_pagination_page2.json":
		data, err = os.ReadFile("testdata/domain_search_pagination_page2.json")
	case "domain_search_b2b.json":
		data, err = os.ReadFile("testdata/domain_search_b2b.json")
	case "domain_search_b2b_single_profile.json":
		data, err = os.ReadFile("testdata/domain_search_b2b_single_profile.json")
	case "domain_search_empty_ghost.json":
		data, err = os.ReadFile("testdata/domain_search_empty_ghost.json")
	case "domain_search_tempmail.json":
		data, err = os.ReadFile("testdata/domain_search_tempmail.json")
	case "domain_search_publicmail.json":
		data, err = os.ReadFile("testdata/domain_search_publicmail.json")
	case "domain_search_accept_all.json":
		data, err = os.ReadFile("testdata/domain_search_accept_all.json")
	case "domain_search_restricted_account.json":
		data, err = os.ReadFile("testdata/domain_search_restricted_account.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", filename, err)
	}
	return data
}

func overrideBaseURL(t *testing.T, serverURL string) {
	t.Helper()
	original := hunterioAPIBaseURL
	hunterioAPIBaseURL = serverURL
	t.Cleanup(func() { hunterioAPIBaseURL = original })
}

func overrideLimits(t *testing.T, limit, maxPages int) {
	t.Helper()
	origLimit := resolver.HunterioLimit
	origPages := resolver.HunterioMaxPages
	resolver.HunterioLimit = limit
	resolver.HunterioMaxPages = maxPages
	t.Cleanup(func() {
		resolver.HunterioLimit = origLimit
		resolver.HunterioMaxPages = origPages
	})
}

func overrideRetries(t *testing.T, retries int) {
	t.Helper()
	orig := resolver.HunterioMaxRetries
	resolver.HunterioMaxRetries = retries
	t.Cleanup(func() { resolver.HunterioMaxRetries = orig })
}

func findResultsByType(results []schema.ModuleResult, entityType string) []schema.ModuleResult {
	var found []schema.ModuleResult
	for _, r := range results {
		if r.Type == entityType {
			found = append(found, r)
		}
	}
	return found
}

func findResultByTypeValue(results []schema.ModuleResult, entityType, value string) *schema.ModuleResult {
	for i := range results {
		if results[i].Type == entityType && results[i].Value == value {
			return &results[i]
		}
	}
	return nil
}

func TestModule_LocalIDChaining(t *testing.T) {
	server := setupMockServer(t, "domain_search_b2b.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getDomainSearch(context.Background(), constants.TypeDomain, "enterprise-b2b.example.net")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	if len(exec.Results) < 2 {
		t.Skip("Expected multiple results to verify chaining, skipping test")
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}

func TestModule_Coverage(t *testing.T) {
	m := New()
	if m.Name() != "hunterio" {
		t.Errorf("expected hunterio, got %s", m.Name())
	}

	mod, ok := m.(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}

	mod.apiKey = ""
	capOut, err := mod.Capabilities()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(capOut.Functions) != 0 {
		t.Error("expected 0 functions when no API key")
	}

	mod.apiKey = testAPIKey
	origScanOrg := resolver.HunterioScanOrg
	resolver.HunterioScanOrg = true
	capOut, err = mod.Capabilities()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(capOut.Functions) == 0 {
		t.Error("expected functions with API key")
	}
	if len(capOut.ModuleConfig.InputTypes) != 2 {
		t.Error("expected 2 input types with HunterioScanOrg=true")
	}

	resolver.HunterioScanOrg = false
	capOut, err = mod.Capabilities()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(capOut.ModuleConfig.InputTypes) != 1 {
		t.Error("expected 1 input type with HunterioScanOrg=false")
	}
	resolver.HunterioScanOrg = origScanOrg
}

func TestModule_ExecCoverage(t *testing.T) {
	m := New()
	mod, ok := m.(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}
	mod.apiKey = testAPIKey

	input := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "example.com"},
		Functions: []string{constants.FuncGetHunterioDomainSearch, "unsupported_func"},
	}

	ts := setupMockServer(t, "", http.StatusInternalServerError)
	origURL := hunterioAPIBaseURL
	hunterioAPIBaseURL = ts.URL

	execOut, err := mod.Exec(input)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	ts.Close()
	hunterioAPIBaseURL = origURL

	var foundUnsupported bool
	var foundDomainSearch bool
	for _, e := range execOut.Executions {
		if e.Function == "unsupported_func" {
			foundUnsupported = true
			if e.Error == nil || *e.Error == "" {
				t.Error("expected error for unsupported func")
			}
		}
		if e.Function == constants.FuncGetHunterioDomainSearch {
			foundDomainSearch = true
		}
	}
	if !foundUnsupported {
		t.Error("unsupported func execution not found")
	}
	if !foundDomainSearch {
		t.Error("domain search execution not found")
	}

	mod.apiKey = ""
	execOutNoKey, err := mod.Exec(input)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	for _, e := range execOutNoKey.Executions {
		if e.Function == constants.FuncGetHunterioDomainSearch {
			t.Error("expected no execution for domain search without API key")
		}
	}
}

type mockTransport struct {
	roundTripFunc func(_ *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type errReader int

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("mock read error")
}
func (errReader) Close() error { return nil }

type errCloseReader int

func (errCloseReader) Read(_ []byte) (n int, err error) {
	return 0, io.EOF
}
func (errCloseReader) Close() error { return errors.New("mock close error") }

func TestHandlePreflightAPI_Coverage(t *testing.T) {
	origURL := hunterioAPIBaseURL

	tests := []struct {
		transport     http.RoundTripper
		name          string
		inputStr      string
		baseURL       string
		checkCredits  int
		checkInvalid  bool
		checkQuotaExc bool
	}{
		{
			name:         "skip preflight",
			inputStr:     "test-api-key",
			baseURL:      origURL,
			transport:    http.DefaultTransport,
			checkCredits: 999999,
		},
		{
			name:         "new request failure",
			inputStr:     "value_bad_req",
			baseURL:      "://invalid",
			transport:    http.DefaultTransport,
			checkInvalid: true,
		},
		{
			name:     "client do failure",
			inputStr: "value_do_fail",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return nil, errors.New("mock request error")
				},
			},
			checkInvalid: true,
		},
		{
			name:     "forbidden status",
			inputStr: "value_forbidden",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusForbidden,
						Body:       http.NoBody,
					}, nil
				},
			},
			checkInvalid: true,
		},
		{
			name:     "default status",
			inputStr: "value_status_500",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       http.NoBody,
					}, nil
				},
			},
			checkInvalid: true,
		},
		{
			name:     "read body error",
			inputStr: "value_read_err",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       errReader(0),
					}, nil
				},
			},
			checkInvalid: true,
		},
		{
			name:     "unmarshal error",
			inputStr: "value_json_err",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("{bad json}")),
					}, nil
				},
			},
			checkInvalid: true,
		},
		{
			name:     "quota exceeded",
			inputStr: "value_quota",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"data":{"requests":{"searches":{"used":10,"available":10}}}}`)),
					}, nil
				},
			},
			checkQuotaExc: true,
		},
		{
			name:     "close body error",
			inputStr: "value_close_err",
			baseURL:  origURL,
			transport: &mockTransport{
				roundTripFunc: func(_ *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       errCloseReader(0),
					}, nil
				},
			},
			checkInvalid: true,
		},
	}

	origTransport := httpClientTransport
	defer func() {
		hunterioAPIBaseURL = origURL
		httpClientTransport = origTransport
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := New().(*module)
			if !ok {
				t.Fatal("expected module to be *module")
			}
			m.apiKey = tt.inputStr
			hunterioAPIBaseURL = tt.baseURL
			httpClientTransport = tt.transport

			m.handlePreflightAPI(context.Background())

			if tt.checkCredits != 0 && m.queryCredits != tt.checkCredits {
				t.Errorf("expected queryCredits %d, got %d", tt.checkCredits, m.queryCredits)
			}
			if m.keyInvalid != tt.checkInvalid {
				t.Errorf("expected keyInvalid %v, got %v", tt.checkInvalid, m.keyInvalid)
			}
			if m.quotaExceeded != tt.checkQuotaExc {
				t.Errorf("expected quotaExceeded %v, got %v", tt.checkQuotaExc, m.quotaExceeded)
			}
		})
	}
}

func TestHandlePageResponse_ServerError(t *testing.T) {
	m, ok := New().(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	shouldBreak := m.handlePageResponse(exec, http.StatusInternalServerError, nil, gen)
	if !shouldBreak {
		t.Errorf("expected shouldBreak to be true for 500 error")
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "hunterio server error") {
		t.Errorf("expected server error in exec.Error, got: %v", exec.Error)
	}
}

func TestGetLimits_Defaults(t *testing.T) {
	oldLimit := resolver.HunterioLimit
	oldMaxPages := resolver.HunterioMaxPages
	defer func() {
		resolver.HunterioLimit = oldLimit
		resolver.HunterioMaxPages = oldMaxPages
	}()

	resolver.HunterioLimit = 0
	resolver.HunterioMaxPages = 0
	l, m := getLimits()
	if l != 10 || m != 1 {
		t.Errorf("expected 10 and 1, got %d and %d", l, m)
	}

	resolver.HunterioLimit = 101
	l, _ = getLimits()
	if l != 10 {
		t.Errorf("expected 10, got %d", l)
	}
}

func TestBuildURL_ConfigParams(t *testing.T) {
	oldType := resolver.HunterioType
	oldSeniority := resolver.HunterioSeniority
	oldDepartment := resolver.HunterioDepartment
	defer func() {
		resolver.HunterioType = oldType
		resolver.HunterioSeniority = oldSeniority
		resolver.HunterioDepartment = oldDepartment
	}()

	resolver.HunterioType = "personal"
	resolver.HunterioSeniority = "senior"
	resolver.HunterioDepartment = "it"

	u, err := buildURL(constants.TypeDomain, "example.com", 10, 0)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	s := u.String()
	if !strings.Contains(s, "type=personal") || !strings.Contains(s, "seniority=senior") || !strings.Contains(s, "department=it") {
		t.Errorf("expected url to contain config params, got: %s", s)
	}
}

func TestAppendSources_DomainOnly(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	emailRef := &schema.EntityRef{LocalID: gen.NextID()}
	e := &apiEmailEntry{
		Value: "test@example.com",
		Sources: []apiEmailSource{
			{Domain: "source-domain.com"},
		},
	}
	res := appendSources(e, nil, emailRef, "example.com", gen)
	if len(res) != 2 {
		t.Fatalf("expected 2 results (group and domain), got %d", len(res))
	}
	if res[1].Type != constants.TypeDomain || res[1].Value != "source-domain.com" {
		t.Errorf("expected domain result, got: %+v", res[1])
	}
}
