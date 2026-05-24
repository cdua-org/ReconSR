package haveibeenpwned

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
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
