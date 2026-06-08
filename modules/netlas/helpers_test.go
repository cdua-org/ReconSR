package netlas

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"cdua-org/ReconSR/schema"
)

const (
	testAPIKey          = "test-api-key"
	testNameFullDomain  = "FullDomain"
	testNameFullIP      = "FullIP"
	testNameEmptySource = "EmptySource"
	testNameMinimal     = "Minimal"
	testIP198           = "198.51.100.42"
)

func setupMockServer(t *testing.T, responseBody []byte) *httptest.Server {
	t.Helper()
	usersData := []byte(`{"plan": {"coins": 100000000, "limit_per_one_download": 10000000}}`)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)

		if strings.Contains(r.URL.Path, "/users/current") {
			if _, err := w.Write(usersData); err != nil {
				t.Errorf("write err: %v", err)
			}
			return
		}

		if strings.Contains(r.URL.Path, "/domains_count") {
			if _, err := w.Write([]byte(`{"count": 5}`)); err != nil {
				t.Errorf("write err: %v", err)
			}
			return
		}

		if _, err := w.Write(responseBody); err != nil {
			t.Errorf("write err: %v", err)
		}
	}))
}

var fixtureMap = map[string]string{
	"domain_responses.json":               "testdata/domain_responses.json",
	"domain_responses_dead.json":          "testdata/domain_responses_dead.json",
	"domain_responses_empty_source.json":  "testdata/domain_responses_empty_source.json",
	"domain_responses_minimal.json":       "testdata/domain_responses_minimal.json",
	"domain_responses_no_whois.json":      "testdata/domain_responses_no_whois.json",
	"domain_responses_subdomain.json":     "testdata/domain_responses_subdomain.json",
	"domain_responses_not_published.json": "testdata/domain_responses_not_published.json",
	"ip_responses.json":                   "testdata/ip_responses.json",
	"ip_responses_empty_source.json":      "testdata/ip_responses_empty_source.json",
	"ip_responses_minimal.json":           "testdata/ip_responses_minimal.json",
	"ip_responses_empty_whois.json":       "testdata/ip_responses_empty_whois.json",
	"ip_responses_invalid_cidr.json":      "testdata/ip_responses_invalid_cidr.json",
	"ip_download.json":                    "testdata/ip_download.json",
	"domain_download.json":                "testdata/domain_download.json",
}

func readNetlasFixture(t *testing.T, filename string) []byte {
	t.Helper()
	path, ok := fixtureMap[filename]
	if !ok {
		t.Fatalf("unsupported fixture %s", filename)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", filename, err)
	}
	return data
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

func requireValidSourceChaining(t *testing.T, results []schema.ModuleResult, targetType, targetValue string) {
	t.Helper()
	seen := make(map[int]bool)

	for _, res := range results {
		if res.LocalID != 0 {
			seen[res.LocalID] = true
		}
	}

	for _, res := range results {
		if res.Source == nil {
			continue
		}
		if res.Source.LocalID != 0 {
			if !seen[res.Source.LocalID] {
				t.Errorf("Source LocalID %d not found in results for type %s value %s", res.Source.LocalID, res.Type, res.Value)
			}
		} else if res.Source.Type != targetType || res.Source.Value != targetValue {
			t.Errorf("Source (Type=%s, Value=%s) has LocalID=0 but does NOT match target (%s, %s)",
				res.Source.Type, res.Source.Value, targetType, targetValue)
		}
	}
}
