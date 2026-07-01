package haveibeenpwned

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const testAPIKey = "test_key"

func setupMockServer(t *testing.T, fixtureName string, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/breachedaccount/", func(w http.ResponseWriter, _ *http.Request) {
		if status == http.StatusTooManyRequests {
			w.Header().Set("retry-after", "1")
		}

		if fixtureName == "" {
			w.WriteHeader(status)
			if status == http.StatusTooManyRequests {
				if _, err := w.Write([]byte(`{"statusCode": 429, "message": "Rate limit is exceeded."}`)); err != nil {
					t.Logf("write failed: %v", err)
				}
			}
			return
		}

		data, err := os.ReadFile(filepath.Join("testdata", filepath.Clean(fixtureName)))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", fixtureName, err)
		}
		w.WriteHeader(status)
		if _, err := w.Write(data); err != nil {
			t.Logf("write failed: %v", err)
		}
	})

	return httptest.NewServer(mux)
}

func overrideBaseURL(t *testing.T, serverURL string) {
	t.Helper()
	original := hibpAPIBaseURL
	hibpAPIBaseURL = serverURL
	t.Cleanup(func() { hibpAPIBaseURL = original })
}

func overrideRetries(t *testing.T, retries int) {
	t.Helper()
	orig := resolver.HaveIBeenPwnedMaxRetries
	resolver.HaveIBeenPwnedMaxRetries = retries
	t.Cleanup(func() { resolver.HaveIBeenPwnedMaxRetries = orig })
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

func TestGetEmailBreaches_Success(t *testing.T) {
	server := setupMockServer(t, "multiple-breaches.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getEmailBreaches(context.Background(), "user@example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	breaches := findResultsByType(exec.Results, constants.TypeBreach)
	if len(breaches) != 5 {
		t.Errorf("expected 5 breaches, got %d", len(breaches))
	}

	if findResultByTypeValue(exec.Results, constants.TypeBreach, "FakePwnList") == nil {
		t.Errorf("missing breach FakePwnList")
	}

	dataClasses := findResultsByType(exec.Results, constants.TypeLeakedData)
	if len(dataClasses) != 4 {
		t.Errorf("expected 4 data classes, got %d", len(dataClasses))
	}

	if exec.RawData == "" {
		t.Errorf("expected non-empty RawData")
	}
}

func TestGetEmailBreaches_NotFound(t *testing.T) {
	server := setupMockServer(t, "", http.StatusNotFound)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getEmailBreaches(context.Background(), "clean@example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(exec.Results))
	}
}

func TestGetEmailBreaches_RateLimitExceeded(t *testing.T) {
	server := setupMockServer(t, "", http.StatusTooManyRequests)
	defer server.Close()

	overrideBaseURL(t, server.URL)
	overrideRetries(t, 2)

	m := &module{apiKey: testAPIKey}
	start := time.Now()
	exec := m.getEmailBreaches(context.Background(), "user@example.com")
	elapsed := time.Since(start)

	if exec.Error == nil {
		t.Fatalf("expected error on rate limit exceeded after retries")
	}

	if *exec.Error != "haveibeenpwned rate limit exceeded: HTTP 429" {
		t.Errorf("unexpected error message: %s", *exec.Error)
	}

	if elapsed < 1*time.Second {
		t.Errorf("expected delay from retry-after, took %v", elapsed)
	}
}

func TestGetEmailBreaches_Unauthorized(t *testing.T) {
	server := setupMockServer(t, "", http.StatusUnauthorized)
	defer server.Close()

	overrideBaseURL(t, server.URL)
	overrideRetries(t, 1)

	m := &module{apiKey: testAPIKey}
	exec := m.getEmailBreaches(context.Background(), "user@example.com")

	if exec.Error == nil {
		t.Fatalf("expected error")
	}

	if *exec.Error != "haveibeenpwned api key is unauthorized: HTTP 401" {
		t.Errorf("unexpected error message: %s", *exec.Error)
	}
}

func TestGetEmailBreaches_DemoMode(t *testing.T) {
	demoKey := "demo-api-key"
	m := &module{apiKey: demoKey}
	exec := m.getEmailBreaches(context.Background(), "user@example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
	}

	breaches := findResultsByType(exec.Results, constants.TypeBreach)
	if len(breaches) != 5 {
		t.Errorf("expected 5 breaches in demo mode, got %d", len(breaches))
	}

	exec2 := m.getEmailBreaches(context.Background(), "user2@example.com")
	if len(exec2.Results) != 0 {
		t.Errorf("expected empty results on second demo call, got %d", len(exec2.Results))
	}
}

func TestModule_LocalIDChaining(t *testing.T) {
	server := setupMockServer(t, "multiple-breaches.json", http.StatusOK)
	defer server.Close()

	overrideBaseURL(t, server.URL)

	m := &module{apiKey: testAPIKey}
	exec := m.getEmailBreaches(context.Background(), "user@example.com")

	if exec.Error != nil {
		t.Fatalf("expected no error, got: %s", *exec.Error)
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
	if m.Name() != "haveibeenpwned" {
		t.Errorf("expected haveibeenpwned, got %s", m.Name())
	}

	mod, ok := m.(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}

	mod.apiKey = ""
	capOut, err := mod.Capabilities()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(capOut.Functions) != 0 {
		t.Error("expected 0 functions when no API key")
	}

	mod.apiKey = "test_key"
	capOut, err = mod.Capabilities()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(capOut.Functions) == 0 {
		t.Error("expected functions with API key")
	}

	origDelay := resolver.HaveIBeenPwnedDelayMs
	resolver.HaveIBeenPwnedDelayMs = 50
	defer func() { resolver.HaveIBeenPwnedDelayMs = origDelay }()

	mod.lastReqTime = time.Now()
	mod.waitRateLimit()

	input := schema.ModuleInput{
		Target:    schema.Entity{Value: "test@example.com"},
		Functions: []string{constants.FuncGetEmailBreaches, "unsupported_func"},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	origURL := hibpAPIBaseURL
	hibpAPIBaseURL = ts.URL
	defer func() { hibpAPIBaseURL = origURL }()

	out, err := mod.Exec(input)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(out.Executions) != 2 {
		t.Fatalf("expected 2 executions, got %d", len(out.Executions))
	}

	foundUnsupported := false
	for _, e := range out.Executions {
		if e.Function == "unsupported_func" {
			foundUnsupported = true
			if e.Error == nil || *e.Error == "" {
				t.Error("expected error for unsupported func")
			}
		}
	}
	if !foundUnsupported {
		t.Error("unsupported func execution not found")
	}
}

func TestDemoCoverage(t *testing.T) {
	m, ok := New().(*module)
	if !ok {
		t.Fatal("expected module to be *module")
	}
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{}

	origRead := readDemoFile
	readDemoFile = func(_ string) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	m.demoFired.Store(false)
	m.getEmailBreachesDemo(exec, "test@example.com", gen)
	if exec.Error == nil || *exec.Error == "" {
		t.Error("expected error for read fail")
	}
	readDemoFile = origRead

	origUnmarshal := unmarshalJSON
	unmarshalJSON = func(_ []byte, _ any) error {
		return errors.New("mock unmarshal error")
	}
	m.demoFired.Store(false)
	exec = &schema.ModuleExecution{}
	m.getEmailBreachesDemo(exec, "test@example.com", gen)
	if exec.Error == nil || *exec.Error == "" {
		t.Error("expected error for unmarshal fail")
	}
	unmarshalJSON = origUnmarshal
}

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.roundTripFunc != nil {
		return m.roundTripFunc(req)
	}
	return nil, errors.New("not implemented")
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errors.New("mock read error") }
func (errReader) Close() error               { return errors.New("mock close error") }

func TestAPICoverage(t *testing.T) {
	overrideRetries(t, 2)
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	m := &module{apiKey: testAPIKey}

	origURL := hibpAPIBaseURL
	defer func() { hibpAPIBaseURL = origURL }()

	origTransport := httpClientTransport
	defer func() { httpClientTransport = origTransport }()

	hibpAPIBaseURL = "http://\x7f"
	m.getEmailBreaches(context.Background(), "user@example.com")

	hibpAPIBaseURL = "http://127.0.0.1:0"
	m.getEmailBreaches(context.Background(), "user@example.com")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("{bad json")); err != nil {
			t.Logf("write failed: %v", err)
		}
	}))
	hibpAPIBaseURL = ts.URL
	m.getEmailBreaches(context.Background(), "user@example.com")
	ts.Close()

	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	hibpAPIBaseURL = ts500.URL
	m.getEmailBreaches(context.Background(), "user@example.com")
	ts500.Close()

	ts429bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("retry-after", "invalid")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	hibpAPIBaseURL = ts429bad.URL
	m.getEmailBreaches(context.Background(), "user@example.com")
	ts429bad.Close()

	ts400 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(`{"message": "custom err"}`)); err != nil {
			t.Logf("write failed: %v", err)
		}
	}))
	hibpAPIBaseURL = ts400.URL
	m.getEmailBreaches(context.Background(), "user@example.com")
	ts400.Close()

	httpClientTransport = &mockTransport{
		roundTripFunc: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReader{},
			}, nil
		},
	}
	hibpAPIBaseURL = "http://example.com"
	m.getEmailBreaches(context.Background(), "user@example.com")
}
