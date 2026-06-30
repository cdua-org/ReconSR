package virustotal

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type domainFixtureRun struct {
	exec schema.ModuleExecution
	mock *vtMockServer
}

func TestModuleExecDomainFixtureContract(t *testing.T) {
	run := executeDomainFixture(t)

	t.Run("request flow", func(t *testing.T) {
		assertDomainRequestFlow(t, run.mock)
	})
	t.Run("subdomain extraction", func(t *testing.T) {
		assertDomainSubdomainExtraction(t, run.exec.Results)
	})
	t.Run("dns extraction", func(t *testing.T) {
		assertDomainDNSExtraction(t, run.exec.Results)
	})
	t.Run("threat extraction", func(t *testing.T) {
		assertDomainThreatExtraction(t, run.exec.Results)
	})
	t.Run("stable metadata extraction", func(t *testing.T) {
		assertDomainStableMetadataExtraction(t, run.exec.Results)
	})
	t.Run("certificate extraction", func(t *testing.T) {
		assertDomainCertificateExtraction(t, run.exec.Results)
	})
	t.Run("ignored whois and rdap", func(t *testing.T) {
		assertDomainIgnoredWhoisAndRDAP(t, run.exec.Results)
	})
	t.Run("subdomain certificate scope", func(t *testing.T) {
		assertSubdomainCertificateScope(t, run.exec.Results)
	})

	requireUniqueLocalIDs(t, run.exec.Results)
}

func executeDomainFixture(t *testing.T) domainFixtureRun {
	t.Helper()

	domainBody := loadVTFixture(t, "domain_page1.json")
	subdomainsPage1 := loadVTFixture(t, "subdomains_page1.json")
	subdomainsPage2 := loadVTFixture(t, "subdomains_page2.json")

	resolver.VirustotalDelayMs = 50
	defer func() { resolver.VirustotalDelayMs = 15000 }()

	responses := map[string]string{
		"/api/v3/domains/" + fixtureDomainTarget:                                                                    domainBody,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40":                                           subdomainsPage1,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2": subdomainsPage2,
	}

	mock, server := newVTMockServer(t, responses, nil)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}
	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: fixtureDomainTarget})
	if exec.Error != nil {
		t.Fatalf("unexpected execution error: %q", *exec.Error)
	}

	return domainFixtureRun{exec: exec, mock: mock}
}

func assertDomainRequestFlow(t *testing.T, mock *vtMockServer) {
	t.Helper()

	rootReq := assertSinglePathHit(t, mock, "/api/v3/domains/"+fixtureDomainTarget)
	page1Req := assertSinglePathHit(t, mock, "/api/v3/domains/"+fixtureDomainTarget+"/subdomains?limit=40")
	page2Req := assertSinglePathHit(t, mock, "/api/v3/domains/"+fixtureDomainTarget+"/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2")
	assertRequestAPIKey(t, mock.allRequests(), fixtureTestAPIKey)
	assertMinimumGap(t, rootReq, page1Req, "domain phase transition")
	assertMinimumGap(t, page1Req, page2Req, "domain pagination")
}

func assertDomainSubdomainExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	subdomain := requireResult(t, results, "discovered subdomain node", func(result schema.ModuleResult) bool {
		return result.Value == fixtureAPISubdomain && result.Category == constants.CategoryNode
	})
	if subdomain.Source != nil {
		t.Fatalf("expected subdomain source to be nil (implicitly pointing to target), got %s", describeSource(subdomain.Source))
	}

	assertDomainWildcardSAN(t, results)
	assertDomainRegularSAN(t, results)
	assertDomainOutOfScopeSAN(t, results)
}

func assertDomainWildcardSAN(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	wildcardSAN := requireResult(t, results, "wildcard SAN node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSubdomain && result.Value == "partners.target-example.com"
	})
	if wildcardSAN.Category != constants.CategoryNode {
		t.Fatalf("expected wildcard SAN to be a node, got %+v", wildcardSAN)
	}
	if !slices.Contains(wildcardSAN.Tags, constants.TagSan) || !slices.Contains(wildcardSAN.Tags, constants.TagWildcard) {
		t.Fatalf("expected SAN and wildcard tags, got %+v", wildcardSAN.Tags)
	}
	if wildcardSAN.Context != "" {
		t.Fatalf("expected empty wildcard SAN context, got %q", wildcardSAN.Context)
	}
}

func assertDomainRegularSAN(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	loginSAN := requireResult(t, results, "regular SAN node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSubdomain && result.Value == "login.target-example.com"
	})
	if loginSAN.Category != constants.CategoryNode {
		t.Fatalf("expected SAN to be a node, got %+v", loginSAN)
	}
	if !slices.Contains(loginSAN.Tags, constants.TagSan) {
		t.Fatalf("expected SAN tag, got %+v", loginSAN.Tags)
	}
}

func assertDomainOutOfScopeSAN(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	oosSAN := requireResult(t, results, "out of scope SAN node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeDomain && result.Value == "example.net"
	})
	if oosSAN.Category != constants.CategoryNode {
		t.Fatalf("expected out-of-scope SAN to be a node, got %+v", oosSAN)
	}
	if !slices.Contains(oosSAN.Tags, constants.TagSan) {
		t.Fatalf("expected SAN tag, got %+v", oosSAN.Tags)
	}
	if !oosSAN.OutOfScope {
		t.Fatalf("expected out-of-scope SAN to be marked out of scope, got %+v", oosSAN)
	}
}

func assertDomainDNSExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	deepA := requireResult(t, results, "deep A record linked to api subdomain", func(result schema.ModuleResult) bool {
		return result.Value == "192.0.2.20" && result.Source != nil && result.Source.Value == fixtureAPISubdomain
	})
	if deepA.Category != constants.CategoryNode {
		t.Fatalf("expected deep A record to be a node, got %+v", deepA)
	}

	deepCNAME := requireResult(t, results, "deep CNAME linked to api subdomain", func(result schema.ModuleResult) bool {
		return result.Value == "edge.target-example.com" && result.Source != nil && result.Source.Value == fixtureAPISubdomain
	})
	if deepCNAME.Category != constants.CategoryNode {
		t.Fatalf("expected deep CNAME to be a node, got %+v", deepCNAME)
	}
	if !slices.Contains(deepCNAME.Tags, constants.TagCNAME) {
		t.Fatalf("expected deep CNAME to have tag %q, got tags %v", constants.TagCNAME, deepCNAME.Tags)
	}
	if deepCNAME.OutOfScope {
		t.Fatalf("expected deep CNAME to remain in scope relative to root domain, got %+v", deepCNAME)
	}

	requireResult(t, results, "CAA property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCAA && strings.Contains(result.Value, "ca.example.org")
	})

	caaAuthority := requireResult(t, results, "CAA authority node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSubdomain && result.Value == "ca.example.org" && slices.Contains(result.Tags, constants.TagCAA)
	})
	if caaAuthority.Category != constants.CategoryNode {
		t.Fatalf("expected cert_authority to be a node, got %+v", caaAuthority)
	}
}

func assertDomainThreatExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	deepThreat := requireResult(t, results, "deep threat score linked to vpn subdomain", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeThreatScore && result.Source != nil && result.Source.Value == fixtureVPNSubdomain
	})
	if !strings.Contains(deepThreat.Context, "SyntheticEngineVPNA") || !strings.Contains(deepThreat.Context, "SyntheticEngineVPNB") {
		t.Fatalf("expected malicious and suspicious engine names in threat context, got %+v", deepThreat)
	}

	assertTagResult(t, results, "suspicious-udp")
}

func assertDomainStableMetadataExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	requireResult(t, results, "domain JARM property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeJARM && result.Value == "2ad2ad0002ad2ad00042d42d000000syntheticdomain"
	})

	requireResult(t, results, "domain last update property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeDate && strings.Contains(result.Value, "Last Update: 2026-05-09")
	})

	requireResult(t, results, "crowdsourced context property", func(result schema.ModuleResult) bool {
		return result.Category == constants.CategoryProperty && resultTextContains(&result, "Synthetic IOC Context", "Legitimate-looking synthetic website used for parser coverage")
	})

	requireResult(t, results, "category property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCategory && result.Category == constants.CategoryProperty && resultTextContains(&result, "BitDefender", "technology")
	})

	requireResult(t, results, "popularity rank property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeRank && result.Category == constants.CategoryProperty && resultTextContains(&result, "Cloudflare Radar", "6")
	})

	requireResult(t, results, "reputation property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeReputation && strings.Contains(result.Value, "-12") && strings.Contains(result.Value, "Malicious/Suspicious")
	})
}

func assertDomainCertificateExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	certIssuer := requireResult(t, results, "certificate issuer linked to SAN", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertIssuer && result.Source != nil && result.Source.Value == "login.target-example.com"
	})
	if !strings.Contains(certIssuer.Value, "Example Global TLS RSA CA") {
		t.Fatalf("expected certificate issuer summary, got %+v", certIssuer)
	}

	requireResult(t, results, "certificate sha256 fingerprint property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertFingerprint && result.Value == "sha256:synthetic-domain-rsa-sha256-thumbprint"
	})

	requireResult(t, results, "certificate sha1 fingerprint property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertFingerprint && result.Value == "sha1:synthetic-domain-rsa-thumbprint"
	})

	requireResult(t, results, "certificate not after property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertNotAfter && strings.Contains(result.Value, "2027-01-31")
	})
}

func assertDomainIgnoredWhoisAndRDAP(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	assertNoResult(t, results, "raw whois text leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "Administrative city:") || strings.Contains(result.Value, "Domain registrar id:") || strings.Contains(result.Value, "Domain Name: MAIL.TARGET-EXAMPLE.COM") || strings.Contains(result.Value, "Domain Name: NS.TARGET-EXAMPLE.COM")
	})

	assertNoResult(t, results, "raw rdap text leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "2724960_DOMAIN_COM-VRSN") || strings.Contains(result.Value, "rdap_conformance")
	})
}

func assertSubdomainCertificateScope(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	vpnCertExpiry := requireResult(t, results, "vpn subdomain cert not_after", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertNotAfter && result.Source != nil && result.Source.Value == fixtureVPNSubdomain
	})
	if !strings.Contains(vpnCertExpiry.Value, "2027-03-15") {
		t.Fatalf("expected vpn subdomain cert expiration 2027-03-15, got %+v", vpnCertExpiry)
	}

	assertNoResult(t, results, "subdomain SAN leakage", func(result schema.ModuleResult) bool {
		return result.Value == "console.target-example.com" || result.Value == "api-alt.target-example.com" || result.Value == "*.api.target-example.com"
	})

	assertNoResult(t, results, "subdomain certificate fingerprint leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "synthetic-subdomain-thumbprint") || strings.Contains(result.Value, "synthetic-subdomain-sha256-thumbprint")
	})

	assertNoResult(t, results, "subdomain certificate issuer leakage", func(result schema.ModuleResult) bool {
		return strings.Contains(result.Value, "Example E8") || strings.Contains(result.Value, "Example Certificate Authority")
	})
}

func TestParseVTCertificateExpiration(t *testing.T) {
	futureTime := time.Now().UTC().Add(24 * time.Hour)
	pastTime := time.Now().UTC().Add(-24 * time.Hour)

	const keyCert = "last_https_certificate"
	const keyVal = "validity"
	const keyAfter = "not_after"

	tests := []struct {
		name        string
		attr        map[string]any
		wantDateStr string
		wantExpired bool
	}{
		{
			name:        "missing last_https_certificate",
			attr:        map[string]any{"other_field": "dummy_data"},
			wantDateStr: "",
			wantExpired: false,
		},
		{
			name:        "invalid last_https_certificate type",
			attr:        map[string]any{keyCert: 123},
			wantDateStr: "",
			wantExpired: false,
		},
		{
			name: "missing validity field",
			attr: map[string]any{
				keyCert: map[string]any{
					"issuer": "some_issuer",
				},
			},
			wantDateStr: "",
			wantExpired: false,
		},
		{
			name: "missing not_after field",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						"not_before": "2020-01-01 00:00:00",
					},
				},
			},
			wantDateStr: "",
			wantExpired: false,
		},
		{
			name: "invalid not_after type",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: 12345,
					},
				},
			},
			wantDateStr: "",
			wantExpired: false,
		},
		{
			name: "valid future vt time format",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: futureTime.Format(vtTimeFormat),
					},
				},
			},
			wantDateStr: futureTime.UTC().Format(time.DateTime),
			wantExpired: false,
		},
		{
			name: "valid past vt time format",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: pastTime.Format(vtTimeFormat),
					},
				},
			},
			wantDateStr: pastTime.UTC().Format(time.DateTime),
			wantExpired: true,
		},
		{
			name: "valid future rfc3339 format",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: futureTime.Format(time.RFC3339),
					},
				},
			},
			wantDateStr: futureTime.UTC().Format(time.DateTime),
			wantExpired: false,
		},
		{
			name: "valid past rfc3339 format",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: pastTime.Format(time.RFC3339),
					},
				},
			},
			wantDateStr: pastTime.UTC().Format(time.DateTime),
			wantExpired: true,
		},
		{
			name: "unparseable date fallback",
			attr: map[string]any{
				keyCert: map[string]any{
					keyVal: map[string]any{
						keyAfter: "Some Weird Date Format 2026",
					},
				},
			},
			wantDateStr: "Some Weird Date Format 2026",
			wantExpired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDateStr, gotExpired := parseVTCertificateExpiration(tt.attr)
			if gotDateStr != tt.wantDateStr {
				t.Errorf("parseVTCertificateExpiration() gotDateStr = %v, want %v", gotDateStr, tt.wantDateStr)
			}
			if gotExpired != tt.wantExpired {
				t.Errorf("parseVTCertificateExpiration() gotExpired = %v, want %v", gotExpired, tt.wantExpired)
			}
		})
	}
}

func TestDomain_EdgeCases(t *testing.T) {
	const (
		keyPopularityRanks = "popularity_ranks"
		keyCrowdsourcedCtx = "crowdsourced_context"
		keyExtensions      = "extensions"
		keyData            = "data"
	)

	m := &module{}
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()

	appendDomainCategories(exec, map[string]any{}, gen)
	appendDomainCategories(exec, map[string]any{"categories": map[string]any{}}, gen)
	appendDomainCategories(exec, map[string]any{"categories": map[string]any{"prov1": 111}}, gen)

	appendDomainReputation(exec, map[string]any{}, gen)
	appendDomainReputation(exec, map[string]any{vtKeyReputation: float64(10)}, gen)

	appendDomainPopularityRanks(exec, map[string]any{}, gen)
	appendDomainPopularityRanks(exec, map[string]any{keyPopularityRanks: map[string]any{}}, gen)
	appendDomainPopularityRanks(exec, map[string]any{keyPopularityRanks: map[string]any{"prov2": 222}}, gen)
	appendDomainPopularityRanks(exec, map[string]any{keyPopularityRanks: map[string]any{"prov3": map[string]any{}}}, gen)

	appendDomainJARM(exec, map[string]any{}, gen)

	appendDomainCrowdsourcedContext(exec, map[string]any{}, gen)
	appendDomainCrowdsourcedContext(exec, map[string]any{keyCrowdsourcedCtx: []any{}}, gen)
	appendDomainCrowdsourcedContext(exec, map[string]any{keyCrowdsourcedCtx: []any{333}}, gen)
	appendDomainCrowdsourcedContext(exec, map[string]any{keyCrowdsourcedCtx: []any{map[string]any{}}}, gen)

	appendDomainLastUpdate(exec, map[string]any{}, "u1.example.net", gen)

	appendDomainCertificateSummary(exec, map[string]any{}, constants.TypeSubdomain, "u2.example.net", gen)
	appendDomainCertificateSummary(exec, map[string]any{"last_https_certificate": map[string]any{"thumbprint_invalid": 444, "other": "val"}}, constants.TypeSubdomain, "u3.example.net", gen)

	appendVTCertificateSANs(exec, map[string]any{}, constants.TypeSubdomain, "u4.example.net", gen)
	appendVTCertificateSANs(exec, map[string]any{keyExtensions: map[string]any{}}, constants.TypeSubdomain, "u5.example.net", gen)
	appendVTCertificateSANs(exec, map[string]any{keyExtensions: map[string]any{"subject_alternative_name": []any{}}}, constants.TypeSubdomain, "u6.example.net", gen)
	appendVTCertificateSANs(exec, map[string]any{keyExtensions: map[string]any{"subject_alternative_name": []any{555, "invalid u7 !", "dup8.example.net", "dup8.example.net"}}}, constants.TypeSubdomain, "u9.example.net", gen)

	classifyVTCertificateSAN("*.")
	classifyVTCertificateSAN("invalid u10 !")

	if formatVTCertificateIssuer(map[string]any{}) != "" {
		t.Error("expected empty string")
	}

	m.extractSubdomain(map[string]any{}, constants.TypeSubdomain, "u11.example.net", false, exec, gen)
	m.extractSubdomain(map[string]any{"id": "invalid u12 !"}, constants.TypeSubdomain, "u13.example.net", false, exec, gen)
	m.extractSubdomain(map[string]any{"id": "u14.example.net"}, constants.TypeSubdomain, "u15.example.net", false, exec, gen)
	m.extractSubdomain(map[string]any{
		"id": "u16.example.net",
		constants.KeyAttributes: map[string]any{
			"tags": []any{"tag1", "tag2"},
			"last_https_certificate": map[string]any{
				"validity": map[string]any{
					"not_after": "2000-01-01 00:00:00",
				},
			},
		},
	}, constants.TypeSubdomain, "u17.example.net", true, exec, gen)

	m.logIgnoredSubdomainFields(map[string]any{"whois": keyData, "rdap": keyData, "registrar": keyData}, "u18.example.net")

	if len(exec.Results) == 0 {
		t.Error("expected results from edge cases")
	}
}

func TestProcessDomain_Error(t *testing.T) {
	statuses := map[string]int{
		"/api/v3/domains/error.example.com": http.StatusInternalServerError,
	}
	_, server := newVTMockServer(t, nil, statuses)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}

	originalRetries := resolver.VirustotalMaxRetries
	resolver.VirustotalMaxRetries = 0
	defer func() { resolver.VirustotalMaxRetries = originalRetries }()

	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "error.example.com"})
	if exec.Error == nil || !strings.Contains(*exec.Error, "domain metadata failed") {
		t.Errorf("expected domain metadata failed error, got %v", exec.Error)
	}
}

func TestProcessDomain_ExpiredCerts(t *testing.T) {
	originalRetries := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = originalRetries }()

	expiredTime := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	subdomainResp := fmt.Sprintf(`{
		"data": [
			{
				"id": "expired.example.com",
				"attributes": {
					"last_https_certificate": {
						"validity": {
							"not_after": "%s"
						}
					}
				}
			}
		]
	}`, expiredTime)

	statuses := map[string]string{
		"/api/v3/domains/test.example.com":                     `{"data":{"id":"test.example.com","attributes":{}}}`,
		"/api/v3/domains/test.example.com/subdomains?limit=40": subdomainResp,
	}

	mock, server := newVTMockServer(t, statuses, nil)
	defer server.Close()
	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}

	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "test.example.com"})

	found := false
	for _, res := range exec.Results {
		if res.Type == constants.TypeCertExpiredSubdomains && strings.Contains(res.Value, "expired.example.com") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected TypeCertExpiredSubdomains with expired.example.com, results: %+v", exec.Results)
	}
	_ = mock
}

func TestProcessDomain_DisableCertExpiredSubdomains(t *testing.T) {
	originalRetries := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	defer func() { resolver.VirustotalDelayMs = originalRetries }()

	oldVal, hasVal := resolver.Options["DisableCertExpiredSubdomains"]
	resolver.Options["DisableCertExpiredSubdomains"] = "true"
	defer func() {
		if hasVal {
			resolver.Options["DisableCertExpiredSubdomains"] = oldVal
		} else {
			delete(resolver.Options, "DisableCertExpiredSubdomains")
		}
	}()

	expiredTime := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	subdomainResp := fmt.Sprintf(`{
		"data": [
			{
				"id": "expired.example.com",
				"attributes": {
					"last_https_certificate": {
						"validity": {
							"not_after": "%s"
						}
					}
				}
			}
		]
	}`, expiredTime)

	statuses := map[string]string{
		"/api/v3/domains/test2.example.com":                     `{"data":{"id":"test2.example.com","attributes":{}}}`,
		"/api/v3/domains/test2.example.com/subdomains?limit=40": subdomainResp,
	}

	mock, server := newVTMockServer(t, statuses, nil)
	defer server.Close()
	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureTestAPIKey}

	exec := execVT(t, mod, schema.Entity{Type: constants.TypeDomain, Value: "test2.example.com"})

	for _, res := range exec.Results {
		if res.Type == constants.TypeCertExpiredSubdomains {
			t.Errorf("unexpected TypeCertExpiredSubdomains result when disabled: %+v", res)
		}
	}
	_ = mock
}
