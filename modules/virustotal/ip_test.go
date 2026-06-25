package virustotal

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type ipFixtureRun struct {
	exec schema.ModuleExecution
	mock *vtMockServer
}

func TestModuleExecIPFixtureContract(t *testing.T) {
	run := executeIPFixture(t)

	t.Run("request flow", func(t *testing.T) {
		assertIPRequestFlow(t, run.mock)
	})
	t.Run("metadata extraction", func(t *testing.T) {
		assertIPMetadataExtraction(t, run.exec.Results)
	})
	t.Run("passive dns extraction", func(t *testing.T) {
		assertIPPassiveDNSExtraction(t, run.exec.Results)
	})
	t.Run("ignored whois and rdap", func(t *testing.T) {
		assertIPIgnoredWhoisAndRDAP(t, run.exec.Results)
	})

	requireUniqueLocalIDs(t, run.exec.Results)
}

func executeIPFixture(t *testing.T) ipFixtureRun {
	t.Helper()

	ipBody := loadVTFixture(t, "ip_page1.json")
	resolutionsPage1 := loadVTFixture(t, "resolutions_page1.json")
	resolutionsPage2 := loadVTFixture(t, "resolutions_page2.json")

	resolver.VirustotalDelayMs = 50
	defer func() { resolver.VirustotalDelayMs = 15000 }()

	responses := map[string]string{
		"/api/v3/ip_addresses/" + fixtureIPTarget:                                                                      ipBody,
		"/api/v3/ip_addresses/" + fixtureIPTarget + "/resolutions?limit=40":                                            resolutionsPage1,
		"/api/v3/ip_addresses/" + fixtureIPTarget + "/resolutions?limit=40&cursor=synthetic-resolutions-cursor-page-2": resolutionsPage2,
	}

	mock, server := newVTMockServer(t, responses, nil)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}
	exec := execVT(t, mod, schema.Entity{Type: constants.TypeIPv4, Value: fixtureIPTarget})
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %q", *exec.Error)
	}

	return ipFixtureRun{exec: exec, mock: mock}
}

func assertIPRequestFlow(t *testing.T, mock *vtMockServer) {
	t.Helper()

	metaReq := assertSinglePathHit(t, mock, "/api/v3/ip_addresses/"+fixtureIPTarget)
	page1Req := assertSinglePathHit(t, mock, "/api/v3/ip_addresses/"+fixtureIPTarget+"/resolutions?limit=40")
	page2Req := assertSinglePathHit(t, mock, "/api/v3/ip_addresses/"+fixtureIPTarget+"/resolutions?limit=40&cursor=synthetic-resolutions-cursor-page-2")
	assertRequestAPIKey(t, mock.allRequests(), fixtureTestAPIKey)
	assertMinimumGap(t, metaReq, page1Req, "ip phase transition")
	assertMinimumGap(t, page1Req, page2Req, "ip pagination")
}

func assertIPMetadataExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertIPMetadataExtractionCore(t, results)
	assertIPMetadataExtractionGeo(t, results)
}

func assertIPMetadataExtractionCore(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	asn := requireResult(t, results, "ASN result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeASN && result.Value == "64544"
	})
	if asn.Category != constants.CategoryNode {
		t.Fatalf("expected ASN to be a node, got %+v", asn)
	}

	requireResult(t, results, "network cidr result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCIDR && result.Value == "192.0.2.0/24"
	})

	requireResult(t, results, "ip JARM result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeJARM && result.Value == "27d40d40d00040d00042d43d000000syntheticip"
	})

	requireResult(t, results, "ip last update result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeDate && strings.Contains(result.Value, "Last Update: 2026-02-13")
	})

	assertTagResult(t, results, "synthetic")
	assertTagResult(t, results, "network")

	threat := requireResult(t, results, "threat score property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeThreatScore
	})
	if !strings.Contains(threat.Context, "SyntheticIPEngineA") || !strings.Contains(threat.Context, "SyntheticIPEngineB") || !strings.Contains(threat.Context, "SyntheticIPEngineC") {
		t.Fatalf("expected ip threat context to contain malicious and suspicious engines, got %+v", threat)
	}
}

func assertIPMetadataExtractionGeo(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	requireResult(t, results, "as owner result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeOrganization && result.Value == "Example Network Operations"
	})

	requireResult(t, results, "geo result", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeGeo && result.Value == "Country: EX | Continent: NA"
	})
}

func assertIPPassiveDNSExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	for _, host := range []string{
		"gateway.target-example.com",
		"vpn.target-example.com",
		fixtureMailSubdomain,
		fixtureAPISubdomain,
	} {
		result := requireResult(t, results, "passive dns result for "+host, func(result schema.ModuleResult) bool {
			return result.Type == constants.TypeSubdomain && result.Value == host
		})
		if result.Category != constants.CategoryNode {
			t.Fatalf("expected passive dns to be node, got %+v", result)
		}
		if !slices.Contains(result.Tags, constants.TagPDNS) {
			t.Fatalf("expected passive dns to have tag %q, got tags %v", constants.TagPDNS, result.Tags)
		}
	}

	oosPDNS := requireResult(t, results, "out of scope passive dns", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeDomain && result.Value == "example.net"
	})
	if oosPDNS.Category != constants.CategoryNode {
		t.Fatalf("expected out of scope passive dns to be node, got %+v", oosPDNS)
	}
	if !slices.Contains(oosPDNS.Tags, constants.TagPDNS) {
		t.Fatalf("expected out of scope passive dns to have tag %q, got tags %v", constants.TagPDNS, oosPDNS.Tags)
	}
}

func assertIPIgnoredWhoisAndRDAP(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	assertNoResult(t, results, "raw ip whois text leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "inetnum:") || strings.Contains(result.Value, "organisation:")
	})

	assertNoResult(t, results, "raw rdap text leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "ip network") || strings.Contains(result.Value, "rdap_level_0")
	})
}

func TestExtractIPResolution_EdgeCases(t *testing.T) {
	mod := &module{}
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		item map[string]any
		name string
	}{
		{
			name: "missing_attributes",
			item: map[string]any{},
		},
		{
			name: "invalid_attributes_type",
			item: map[string]any{
				constants.KeyAttributes: "not_a_map",
			},
		},
		{
			name: "missing_host_name",
			item: map[string]any{
				constants.KeyAttributes: map[string]any{},
			},
		},
		{
			name: "invalid_host_name_type",
			item: map[string]any{
				constants.KeyAttributes: map[string]any{
					"host_name": 12345,
				},
			},
		},
		{
			name: "invalid_domain_validation",
			item: map[string]any{
				constants.KeyAttributes: map[string]any{
					"host_name": "invalid-domain-[].example",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{}
			mod.extractIPResolution(tt.item, "", exec, gen)
			if len(exec.Results) > 0 {
				t.Fatalf("expected no results, got %d", len(exec.Results))
			}
		})
	}
}

func TestProcessIP_Error(t *testing.T) {
	statuses := map[string]int{
		"/api/v3/ip_addresses/127.0.0.1": http.StatusInternalServerError,
	}
	_, server := newVTMockServer(t, nil, statuses)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}

	originalRetries := resolver.VirustotalMaxRetries
	resolver.VirustotalMaxRetries = 0
	defer func() { resolver.VirustotalMaxRetries = originalRetries }()

	exec := execVT(t, mod, schema.Entity{Type: constants.TypeIPv4, Value: "127.0.0.1"})
	if exec.Error == nil || !strings.Contains(*exec.Error, "IP metadata failed") {
		t.Errorf("expected IP metadata failed error, got %v", exec.Error)
	}
}
