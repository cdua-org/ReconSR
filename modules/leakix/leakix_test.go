package leakix

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"cdua-org/ReconSR/schema"
)

const testKey = "test_key"
const testDomain = "example.com"

func loadLeakixFixture(t *testing.T, filename string) []byte {
	t.Helper()
	var data []byte
	var err error
	switch filename {
	case "service_domain_response.json":
		data, err = os.ReadFile("testdata/service_domain_response.json")
	case "service_ip_response.json":
		data, err = os.ReadFile("testdata/service_ip_response.json")
	case "subdomains_response.json":
		data, err = os.ReadFile("testdata/subdomains_response.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}
	if err != nil {
		t.Fatalf("failed to read testdata %s: %v", filename, err)
	}
	return data
}

func newTestServer(t *testing.T, fixtureName string) func() {
	t.Helper()
	fixtureData := loadLeakixFixture(t, fixtureName)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("api-key") != testKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write(fixtureData); writeErr != nil {
			http.Error(w, writeErr.Error(), http.StatusInternalServerError)
		}
	}))

	originalURL := leakixAPIBaseURL
	leakixAPIBaseURL = ts.URL
	return func() {
		ts.Close()
		leakixAPIBaseURL = originalURL
	}
}

func checkLocalIDs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	emittedIDs := make(map[int]bool)
	for _, res := range results {
		if res.LocalID != 0 {
			if emittedIDs[res.LocalID] {
				t.Errorf("Duplicate LocalID emitted: %d for %s:%s", res.LocalID, res.Type, res.Value)
			}
			emittedIDs[res.LocalID] = true
		}
	}

	for _, res := range results {
		if res.Source != nil && res.Source.LocalID != 0 {
			if !emittedIDs[res.Source.LocalID] {
				t.Errorf("Source references unknown LocalID: %d in %s:%s", res.Source.LocalID, res.Type, res.Value)
			}
		}
	}
}

func TestLeakixModule_Core(t *testing.T) {
	m := New()
	if m.Name() != moduleName {
		t.Errorf("Expected name %s, got %s", moduleName, m.Name())
	}

	_, err := m.Capabilities()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mWithKey := &leakixModule{apiKey: testKey}
	_, err = mWithKey.Capabilities()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestLeakixModule_ExecUnsupported(t *testing.T) {
	m := &leakixModule{apiKey: ""}
	input := schema.ModuleInput{
		Functions: []string{"UnknownFunction"},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("Expected 1 execution, got %d", len(out.Executions))
	}
	if out.Executions[0].Error == nil {
		t.Error("Expected error in execution for unsupported function")
	}
}
