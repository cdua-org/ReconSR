package virustotal

import (
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
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
}

func executeDomainFixture(t *testing.T) domainFixtureRun {
	t.Helper()

	domainBody := loadVTFixture(t, "domain_page1.json")
	subdomainsPage1 := loadVTFixture(t, "subdomains_page1.json")
	subdomainsPage2 := loadVTFixture(t, "subdomains_page2.json")

	withVTDelayConfig(t, 8)

	responses := map[string]string{
		"/api/v3/domains/" + fixtureDomainTarget:                                                                    domainBody,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40":                                           subdomainsPage1,
		"/api/v3/domains/" + fixtureDomainTarget + "/subdomains?limit=40&cursor=synthetic-subdomains-cursor-page-2": subdomainsPage2,
	}

	mock, server := newVTMockServer(t, responses, nil)
	defer server.Close()

	setVTBaseURL(t, server.URL+"/api/v3")

	mod := &module{apiKey: fixtureFixtureAPIKey}
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
	assertRequestAPIKey(t, mock.allRequests(), fixtureFixtureAPIKey)
	assertMinimumGap(t, rootReq, page1Req, "domain phase transition")
	assertMinimumGap(t, page1Req, page2Req, "domain pagination")
}

func assertDomainSubdomainExtraction(t *testing.T, results []schema.ModuleResult) {
	t.Helper()

	subdomain := requireResult(t, results, "discovered subdomain node", func(result schema.ModuleResult) bool {
		return result.Value == fixtureAPISubdomain && result.Category == constants.CategoryNode
	})
	if subdomain.Source == nil || subdomain.Source.Type != constants.TypeDomain || subdomain.Source.Value != fixtureDomainTarget {
		t.Fatalf("expected subdomain source to point to root domain, got %s", describeSource(subdomain.Source))
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
	if wildcardSAN.Context != "*.partners.target-example.com" {
		t.Fatalf("expected wildcard SAN context, got %q", wildcardSAN.Context)
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
		return result.Type == constants.TypeVTThreatScore && result.Source != nil && result.Source.Value == fixtureVPNSubdomain
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
		return result.Type == constants.TypeLastUpdate && strings.Contains(result.Value, "2026-05-09T08:42:44Z")
	})

	requireResult(t, results, "crowdsourced context property", func(result schema.ModuleResult) bool {
		return result.Category == constants.CategoryProperty && resultTextContains(&result, "Synthetic IOC Context", "Legitimate-looking synthetic website used for parser coverage")
	})

	requireResult(t, results, "category property", func(result schema.ModuleResult) bool {
		return result.Category == constants.CategoryProperty && resultTextContains(&result, "BitDefender", "technology")
	})

	requireResult(t, results, "popularity rank property", func(result schema.ModuleResult) bool {
		return result.Category == constants.CategoryProperty && resultTextContains(&result, "Cloudflare Radar", "6")
	})

	requireResult(t, results, "reputation property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeVTReputation && strings.Contains(result.Value, "-12") && strings.Contains(result.Value, "Malicious/Suspicious")
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
