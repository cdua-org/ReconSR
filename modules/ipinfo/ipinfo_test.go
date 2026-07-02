package ipinfo

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModuleMeta(t *testing.T) {
	m := New()
	if m.Name() != "ipinfo" {
		t.Errorf("expected module name 'ipinfo', got %s", m.Name())
	}

	if setErr := os.Setenv("RECONSR_IPINFO", ""); setErr != nil {
		t.Fatalf("setenv: %v", setErr)
	}
	mNoKey := New()
	capsNoKey, err := mNoKey.Capabilities()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(capsNoKey.Functions) != 0 {
		t.Errorf("expected no capabilities without API key, got %v", capsNoKey.Functions)
	}

	if setErr := os.Setenv("RECONSR_IPINFO", "test-api-key"); setErr != nil {
		t.Fatalf("setenv: %v", setErr)
	}
	t.Cleanup(func() {
		if unsetErr := os.Unsetenv("RECONSR_IPINFO"); unsetErr != nil {
			t.Logf("unsetenv failed: %v", unsetErr)
		}
	})

	mWithKey := New()
	caps, err2 := mWithKey.Capabilities()
	if err2 != nil {
		t.Errorf("unexpected error: %v", err2)
	}
	if len(caps.Functions) == 0 || caps.Functions[0] != constants.FuncGetIPInfo {
		t.Errorf("expected FuncGetIPInfo, got %v", caps.Functions)
	}
}

func TestExec_UnsupportedFunction(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "test-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	m := New()
	out, err := m.Exec(schema.ModuleInput{
		Functions: []string{"unknown_function"},
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	exec := out.Executions[0]
	if exec.Error == nil || !strings.Contains(*exec.Error, "unsupported function: unknown_function") {
		t.Errorf("expected unsupported function error, got %v", exec.Error)
	}
}

func TestIPInfo(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "test-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	oldTimeout := resolver.HTTPTimeout
	oldRetries := resolver.MaxRetriesIPMeta
	oldDelay := resolver.RetryBaseDelay
	resolver.HTTPTimeout = 10 * time.Millisecond
	resolver.MaxRetriesIPMeta = 1
	resolver.RetryBaseDelay = 0
	defer func() {
		resolver.HTTPTimeout = oldTimeout
		resolver.MaxRetriesIPMeta = oldRetries
		resolver.RetryBaseDelay = oldDelay
	}()

	tests := []struct {
		assert  func(*testing.T, *schema.ModuleExecution)
		name    string
		target  string
		fixture string
	}{
		{assert: assertLite, name: "Lite", target: "192.0.2.10", fixture: "fake-lite.json"},
		{assert: nil, name: "MaxClean", target: "198.51.100.20", fixture: "fake-max-clean.json"},
		{assert: assertMaxDirty, name: "MaxDirty", target: defaultDemoIP, fixture: defaultDemoFixture},
		{assert: nil, name: "MaxIPv6", target: "2001:db8::8a2e:370:7334", fixture: "fake-max-ipv6.json"},
		{assert: assertNoASN, name: "NoASN", target: "192.0.2.11", fixture: "fake-no-asn.json"},
		{assert: assertMobileNoObj, name: "MobileNoObj", target: "192.0.2.12", fixture: "fake-mobile-no-obj.json"},
		{assert: assertMobileNoName, name: "MobileNoName", target: "192.0.2.13", fixture: "fake-mobile-no-name.json"},
		{assert: assertGeoNoCountry, name: "GeoNoCountry", target: "192.0.2.14", fixture: "fake-geo-no-country.json"},
		{assert: assertGeoFlatFull, name: "GeoFlatFull", target: "192.0.2.15", fixture: "fake-geo-flat-full.json"},
		{assert: assertAnonNoObj, name: "AnonNoObj", target: "192.0.2.16", fixture: "fake-anon-no-obj.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("testdata", tt.fixture))
			if err != nil {
				t.Fatalf("Failed to read fixture: %v", err)
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-api-key" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
				if _, wErr := w.Write(content); wErr != nil {
					t.Logf("write response failed: %v", wErr)
				}
			}))
			defer server.Close()

			oldAPI := defaultAPIURL
			defaultAPIURL = server.URL + "/"
			defer func() {
				defaultAPIURL = oldAPI
			}()

			m := New()
			data := schema.ModuleInput{
				Functions: []string{constants.FuncGetIPInfo},
				Target:    schema.Entity{Type: constants.TypeIPv4, Value: tt.target},
			}
			if tt.name == "MaxIPv6" {
				data.Target.Type = constants.TypeIPv6
			}

			out, err := m.Exec(data)
			if err != nil {
				t.Fatalf("Unexpected exec error: %v", err)
			}

			if len(out.Executions) != 1 {
				t.Fatalf("Expected 1 execution, got %d", len(out.Executions))
			}
			exec := out.Executions[0]
			if exec.Error != nil {
				t.Fatalf("Unexpected execution error: %v", *exec.Error)
			}
			if len(exec.Results) == 0 {
				t.Fatalf("Expected results, got 0")
			}

			if tt.assert != nil {
				tt.assert(t, &exec)
			}

			requireUniqueLocalIDs(t, exec.Results)
		})
	}
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
	}
}
