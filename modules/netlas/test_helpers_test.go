package netlas

import (
	"net/http"
	"net/http/httptest"
	"os"
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
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header 'Bearer test-api-key', got '%s'", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(responseBody); err != nil {
			t.Errorf("write err: %v", err)
		}
	}))
}

func readNetlasFixture(t *testing.T, filename string) []byte {
	t.Helper()
	var data []byte
	var err error

	switch filename {
	case "domain_responses.json":
		data, err = os.ReadFile("testdata/domain_responses.json")
	case "domain_responses_dead.json":
		data, err = os.ReadFile("testdata/domain_responses_dead.json")
	case "domain_responses_empty_source.json":
		data, err = os.ReadFile("testdata/domain_responses_empty_source.json")
	case "domain_responses_minimal.json":
		data, err = os.ReadFile("testdata/domain_responses_minimal.json")
	case "domain_responses_no_whois.json":
		data, err = os.ReadFile("testdata/domain_responses_no_whois.json")
	case "domain_responses_subdomain.json":
		data, err = os.ReadFile("testdata/domain_responses_subdomain.json")
	case "domain_responses_not_published.json":
		data, err = os.ReadFile("testdata/domain_responses_not_published.json")
	case "ip_responses.json":
		data, err = os.ReadFile("testdata/ip_responses.json")
	case "ip_responses_empty_source.json":
		data, err = os.ReadFile("testdata/ip_responses_empty_source.json")
	case "ip_responses_minimal.json":
		data, err = os.ReadFile("testdata/ip_responses_minimal.json")
	case "ip_responses_empty_whois.json":
		data, err = os.ReadFile("testdata/ip_responses_empty_whois.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}

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
