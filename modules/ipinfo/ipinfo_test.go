package ipinfo

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	resolver.HTTPTimeout = 2 * time.Second
	resolver.MaxRetriesIPMeta = 1
	resolver.RetryBaseDelay = 0
	defer func() {
		resolver.HTTPTimeout = oldTimeout
		resolver.MaxRetriesIPMeta = oldRetries
		resolver.RetryBaseDelay = oldDelay
	}()

	tests := []struct {
		name    string
		target  string
		fixture string
	}{
		{"Lite", "192.0.2.10", "fake-lite.json"},
		{"MaxClean", "198.51.100.20", "fake-max-clean.json"},
		{"MaxDirty", defaultDemoIP, defaultDemoFixture},
		{"MaxIPv6", "2001:db8::8a2e:370:7334", "fake-max-ipv6.json"},
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

			switch tt.name {
			case "MaxDirty":
				assertMaxDirty(t, &exec)
			case "Lite":
				assertLite(t, &exec)
			}

			requireUniqueLocalIDs(t, exec.Results)
		})
	}
}

func assertMaxDirty(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}

	getResult := func(typ, val string) *schema.ModuleResult {
		for i, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return &exec.Results[i]
			}
		}
		return nil
	}

	if !hasResult(constants.TypeGeo, "City: AnotherFakeCity | Region: AnotherFakeRegion | Country: AnotherFakeCountry (YY) | Lat/Lon: 1.111100, -1.111100 | Zip: 11111 | TZ: Fake/Timezone_Two") {
		t.Errorf("Missing expected Geo location formatting")
	}
	if !hasResult(constants.TypeDate, "Last Changed: 2000-01-01") {
		t.Errorf("Missing expected Geo or AS Last Changed property")
	}

	verifyMobileLinkage(t, getResult)
	verifyAnonymousLinkage(t, getResult)

	if !hasResult(constants.TypeASN, "AS77777") {
		t.Errorf("Missing ASN node")
	}
}

func verifyMobileLinkage(t *testing.T, getResult func(typ, val string) *schema.ModuleResult) {
	mobileNode := getResult(constants.TypeTag, "mobile")
	if mobileNode == nil {
		t.Errorf("Missing mobile tag")
		return
	}
	if mobileNode.LocalID <= 0 {
		t.Errorf("Mobile node missing LocalID")
		return
	}

	mobileInfo := getResult(constants.TypeInfo, "FakeTelecom (MCC: 999, MNC: 99)")
	if mobileInfo == nil {
		t.Errorf("Missing mobile network info")
	} else if mobileInfo.Source == nil || mobileInfo.Source.LocalID != mobileNode.LocalID {
		t.Errorf("Mobile network info not correctly linked to mobile tag LocalID")
	}
}

func verifyAnonymousLinkage(t *testing.T, getResult func(typ, val string) *schema.ModuleResult) {
	anonNode := getResult(constants.TypeTag, "anonymous")
	if anonNode == nil {
		t.Errorf("Missing anonymous tag")
		return
	}
	if anonNode.LocalID <= 0 {
		t.Errorf("Anonymous node missing LocalID")
		return
	}

	anonInfo := getResult(constants.TypeInfo, "FakeVPN Service")
	if anonInfo == nil {
		t.Errorf("Missing privacy service name")
	} else if anonInfo.Source == nil || anonInfo.Source.LocalID != anonNode.LocalID {
		t.Errorf("Privacy service name not correctly linked to anonymous tag LocalID")
	}

	anonDate := getResult(constants.TypeDate, "Last Seen: 2000-01-01")
	if anonDate == nil {
		t.Errorf("Missing privacy last seen property")
	} else if anonDate.Source == nil || anonDate.Source.LocalID != anonNode.LocalID {
		t.Errorf("Privacy last seen not correctly linked to anonymous tag LocalID")
	}
}

func assertLite(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeGeo, "Country: FakeCountry (XX)") {
		t.Errorf("Missing expected Lite Geo location formatting")
	}
	if !hasResult(constants.TypeASN, "AS99999") {
		t.Errorf("Missing Lite ASN node")
	}
}

func TestIPInfoDemoMode(t *testing.T) {
	if err := os.Setenv("RECONSR_IPINFO", "demo-api-key"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv("RECONSR_IPINFO"); err != nil {
			t.Logf("unsetenv failed: %v", err)
		}
	})

	m := New()
	data := schema.ModuleInput{
		Functions: []string{constants.FuncGetIPInfo},
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: defaultDemoIP},
	}

	out, err := m.Exec(data)
	if err != nil {
		t.Fatalf("Unexpected exec error: %v", err)
	}

	exec := out.Executions[0]
	if exec.Error != nil {
		t.Fatalf("Unexpected execution error: %v", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatalf("Expected results, got 0")
	}

	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}

	if !hasResult(constants.TypeGeo, "City: AnotherFakeCity | Region: AnotherFakeRegion | Country: AnotherFakeCountry (YY) | Lat/Lon: 1.111100, -1.111100 | Zip: 11111 | TZ: Fake/Timezone_Two") {
		t.Errorf("Missing expected Geo location formatting in demo mode")
	}
	if !hasResult(constants.TypeTag, "anonymous") {
		t.Errorf("Missing anonymous tag in demo mode")
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
	}
}
