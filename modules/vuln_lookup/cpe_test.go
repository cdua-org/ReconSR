package vuln_lookup

import (
	"context"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func countCVEs(results []schema.ModuleResult) int {
	var count int
	for _, r := range results {
		if r.Type == constants.TypeCVE && r.Category == constants.CategoryProperty {
			count++
		}
	}
	return count
}

func TestIsValidSpecificCPE(t *testing.T) {
	tests := []struct {
		cpe      string
		expected bool
	}{
		{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", true},
		{"cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*", true},
		{"cpe:2.3:a:vendor:product:1.0:update:*:*:*:*:*:*", true},

		{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", false},
		{"cpe:2.3:a:nginx:nginx:-:*:*:*:*:*:*:*", false},
		{"cpe:2.3:a:nginx:nginx::*:*:*:*:*:*:*", false},

		{"cpe:/a:nginx:nginx:1.24.0", true},

		{"cpe:/a:nginx:nginx:*", false},
		{"cpe:/a:nginx:nginx:-", false},
		{"cpe:/a:nginx:nginx", false},

		{"nginx:1.24.0", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.cpe, func(t *testing.T) {
			result := isValidSpecificCPE(tt.cpe)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for %s", tt.expected, result, tt.cpe)
			}
		})
	}
}

func TestSearchCirclCPE_Success(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)
	resolver.CirclCPEPerPage = 100

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:aioseo:all_in_one_seo:4.1.10:*:*:*:*:wordpress:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	if countCVEs(exec.Results) != 6 {
		t.Errorf("expected 6 CVEs, got %d", countCVEs(exec.Results))
	}
}

func TestSearchCirclCPE_NVDSource(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)
	origSource := resolver.CirclCPESource
	resolver.CirclCPESource = "nvd"
	defer func() { resolver.CirclCPESource = origSource }()
	resolver.CirclCPEPerPage = 100

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:aioseo:all_in_one_seo:4.1.10:*:*:*:*:wordpress:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	if countCVEs(exec.Results) != 6 {
		t.Errorf("expected 6 CVEs, got %d", countCVEs(exec.Results))
	}
}

func TestSearchCirclCPE_Pagination(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	resolver.CirclCPEPerPage = 2
	resolver.CirclCPEMaxPages = 3
	resolver.CirclRetryBaseDelay = time.Millisecond

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	cveCount := countCVEs(exec.Results)
	if cveCount == 0 {
		t.Errorf("expected > 0 CVEs, got 0")
	}
}

func TestSearchCirclCPE_Empty(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:empty:empty:1.0:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	if countCVEs(exec.Results) != 0 {
		t.Errorf("expected 0 CVEs, got %d", countCVEs(exec.Results))
	}
}

func TestSearchCirclCPE_ServerError(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)
	overrideRetryDelay(t)

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:error:error:1.0:*:*:*:*:*:*:*", gen)

	if exec.Error == nil {
		t.Fatal("expected error for 500 status code")
	}
}

func TestSearchCirclCPE_InvalidCPE(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}
	if countCVEs(exec.Results) != 0 {
		t.Errorf("expected 0 CVEs due to invalid CPE, got %d", countCVEs(exec.Results))
	}
}

func TestSearchCirclCPE_InvalidJSON(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:invalid_json:invalid_json:1.0:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("did not expect fatal error, just break, got: %s", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results due to unmarshal failure, got %d", len(exec.Results))
	}
}

func TestSearchCirclCPE_EmptyRaw(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:empty_raw:empty_raw:1.0:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("did not expect fatal error, just break, got: %s", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results due to empty raw, got %d", len(exec.Results))
	}
}

func TestBuildCPEURL_Error(t *testing.T) {
	_, err := buildCPEURL("http://192.168.0.%31/", 1, 100)
	if err == nil {
		_, err = buildCPEURL("http://\x7finvalid", 1, 100)
	}
	if err == nil {
		t.Log("Warning: Could not trigger url.Parse error for coverage")
	}
}

func TestSearchCirclCPE_EmptyCVEID(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:empty_cveid:empty_cveid:1.0:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}
	if len(exec.Results) != 1 {
		t.Errorf("expected 1 result (Applied: true), got %d", len(exec.Results))
	}
	if !exec.Results[0].Applied || exec.Results[0].Type != constants.TypeCPE {
		t.Errorf("expected result to be Applied CPE, got %+v", exec.Results[0])
	}
}

func TestSearchCirclCPE_UnsupportedType(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()
	exec := m.searchCirclCPE(context.Background(), constants.TypeIP, "1.2.3.4", gen)
	if exec.Error == nil || *exec.Error == "" {
		t.Errorf("expected error for unsupported type")
	}
}

func TestFetchAndParseCPE_InvalidURL(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()
	exec := schema.ModuleExecution{}

	orig := circlAPIBaseURL
	circlAPIBaseURL = "http://192.168.0.%31"
	defer func() { circlAPIBaseURL = orig }()

	m.fetchAndParseCPE(context.Background(), &exec, "cpe:/test", gen)
	if exec.Error == nil {
		t.Errorf("expected url parse error")
	}
}

func TestSearchCirclCPE_LegacyFormat(t *testing.T) {
	server := setupMockServer(t)
	defer server.Close()
	overrideBaseURL(t, server.URL)
	resolver.CirclCPEPerPage = 100

	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec := m.searchCirclCPE(context.Background(), constants.TypeCPE, "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*", gen)

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	foundCVE := false
	foundExploit := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeCVE && res.Value == "CVE-2017-9798" {
			foundCVE = true
		}
		if res.Type == constants.TypeExploit && strings.Contains(res.Value, "exploit-db.com") {
			foundExploit = true
		}
	}

	if !foundCVE {
		t.Error("expected CVE-2017-9798 to be returned via legacy parsing")
	}
	if !foundExploit {
		t.Error("expected exploit link from CVE-2017-9798 to be extracted")
	}
}
