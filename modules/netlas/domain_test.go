package netlas

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"slices"
	"strings"
	"testing"
)

func TestGetContactRoleName(t *testing.T) {
	if getContactRoleName("unknown") != "Contact" {
		t.Errorf("expected Contact")
	}
}

func TestNetlasGetDomain(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{testNameFullDomain, "domain_responses.json"},
		{"Dead", "domain_responses_dead.json"},
		{testNameEmptySource, "domain_responses_empty_source.json"},
		{testNameMinimal, "domain_responses_minimal.json"},
		{"NoWhois", "domain_responses_no_whois.json"},
		{"NotPublished", "domain_responses_not_published.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureData := readNetlasFixture(t, tt.fixture)
			server := setupMockServer(t, fixtureData)
			defer server.Close()

			originalURL := netlasAPIBaseURL
			netlasAPIBaseURL = server.URL
			defer func() { netlasAPIBaseURL = originalURL }()

			resolver.MaxRetriesNetlas = 1

			m := &netlasModule{apiKey: testAPIKey}

			targetValue := "example.edu"
			targetType := constants.TypeDomain

			target := schema.Entity{
				Type:  targetType,
				Value: targetValue,
			}

			input := schema.ModuleInput{
				Target:    target,
				Functions: []string{constants.FuncGetNetlasDomain},
			}

			out, err := m.Exec(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out.Executions) != 1 {
				t.Fatalf("expected 1 execution, got %d", len(out.Executions))
			}

			exec := out.Executions[0]
			if exec.Error != nil {
				t.Fatalf("expected no error, got %v", *exec.Error)
			}

			requireUniqueLocalIDs(t, exec.Results)
			requireValidSourceChaining(t, exec.Results, target.Type, target.Value)

			switch tt.name {
			case testNameFullDomain:
				t.Run("PortsAndServices", func(t *testing.T) { assertDomainPortsAndServices(t, exec.Results) })
				t.Run("IoC_URLs", func(t *testing.T) { assertDomainIoCs(t, exec.Results) })
				t.Run("Whois_Contacts_Status", func(t *testing.T) { assertDomainWhois(t, exec.Results) })
				t.Run("DNS_TXT_SPF", func(t *testing.T) { assertDomainDNS(t, exec.Results) })
				t.Run("Software_Deduplication", func(t *testing.T) { assertDomainSoftwareDeduplication(t, exec.Results) })
				t.Run("CVE_Hierarchy", func(t *testing.T) { verifyDomainCVEHierarchy(t, exec.Results) })
				t.Run("Parsed_Domains", func(t *testing.T) { assertParsedDomains(t, exec.Results, 5, false) })
				t.Run("Target_Applied", func(t *testing.T) { assertTargetApplied(t, exec.Results, "example.edu") })
			case testNameMinimal, "NoWhois":
				assertParsedDomains(t, exec.Results, 0, false)
			}
		})
	}
}

func assertResultMatch(t *testing.T, results []schema.ModuleResult, name string, match func(res schema.ModuleResult) bool) {
	t.Helper()
	if !slices.ContainsFunc(results, match) {
		t.Errorf("expected to find %s", name)
	}
}

func assertDomainPortsAndServices(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertResultMatch(t, results, "port 80/tcp http", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypePort && r.Value == "80/tcp http"
	})
	assertResultMatch(t, results, "WordPress service", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeService && strings.Contains(r.Value, "WordPress")
	})
}

func assertDomainIoCs(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertResultMatch(t, results, "IoC URL", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeThreatURL && strings.Contains(r.Value, "example.edu/url")
	})
}

func assertDomainWhois(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertResultMatch(t, results, "person Bob Edu", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypePerson && r.Value == "Bob Edu"
	})
	assertResultMatch(t, results, "contact address", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeAddress && strings.Contains(r.Value, "2 Example Campus")
	})
	assertResultMatch(t, results, "whois server whois.educause.edu", func(r schema.ModuleResult) bool {
		return (r.Type == constants.TypeDomain || r.Type == constants.TypeSubdomain) && r.Value == "whois.educause.edu" && slices.Contains(r.Tags, constants.TagWhoisServer)
	})
	assertResultMatch(t, results, "WHOIS status clientTransferProhibited", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeStatus && r.Value == "clientTransferProhibited"
	})
}

func assertDomainDNS(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertDomainDNSSPF(t, results)
	assertDomainDNSDMARC(t, results)
	assertResultMatch(t, results, "TXT record verification=fake-token-123456789", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeTXT && r.Value == "verification=fake-token-123456789"
	})
	assertResultMatch(t, results, "A record", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIPv4 && r.Value == "198.51.100.1"
	})
	assertResultMatch(t, results, "AAAA record", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIPv6 && r.Value == "2001:db8::1"
	})
	assertResultMatch(t, results, "NS record", func(r schema.ModuleResult) bool {
		return r.Value == "ns1.example.net" && slices.Contains(r.Tags, constants.TagNS)
	})
	assertResultMatch(t, results, "CNAME record", func(r schema.ModuleResult) bool {
		return r.Value == "cname1.example.net" && slices.Contains(r.Tags, constants.TagCNAME)
	})
}

func assertDomainDNSSPF(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertResultMatch(t, results, "SPF domain spf.example.com", func(r schema.ModuleResult) bool {
		return r.Value == "spf.example.com" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF domain a.example.com", func(r schema.ModuleResult) bool {
		return r.Value == "a.example.com" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF domain mx.example.com", func(r schema.ModuleResult) bool {
		return r.Value == "mx.example.com" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF domain exists.example.com", func(r schema.ModuleResult) bool {
		return r.Value == "exists.example.com" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF domain redirect.example.com", func(r schema.ModuleResult) bool {
		return r.Value == "redirect.example.com" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF IPv4 CIDR 198.51.100.0/24", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCIDR && r.Value == "198.51.100.0/24" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF IPv6 CIDR 2001:db8::/32", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCIDR && r.Value == "2001:db8::/32" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF IPv4 198.51.100.10", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIPv4 && r.Value == "198.51.100.10" && slices.Contains(r.Tags, constants.TagSPF)
	})
	assertResultMatch(t, results, "SPF IPv6 2001:db8::10", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIPv6 && r.Value == "2001:db8::10" && slices.Contains(r.Tags, constants.TagSPF)
	})
}

func assertDomainDNSDMARC(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertResultMatch(t, results, "DMARC email dmarc@example.com", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeEmail && r.Value == "dmarc@example.com"
	})
	assertResultMatch(t, results, "DMARC email forensic@example.com", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeEmail && r.Value == "forensic@example.com"
	})
}

func assertDomainSoftwareDeduplication(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	apacheCount := 0
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeService {
			if strings.Contains(res.Value, "Apache HTTP Server") && strings.Contains(res.Value, "2.4") {
				apacheCount++
			} else if strings.Contains(res.Value, "Apache") && !strings.Contains(res.Value, "HTTP Server") && strings.Contains(res.Value, "2.4") {
				t.Errorf("expected Apache to be deduplicated into Apache HTTP Server, but found base Apache")
			}
		}
	}
	if apacheCount != 1 {
		t.Errorf("expected exactly 1 Apache HTTP Server 2.4 service due to CPE deduplication, got %d", apacheCount)
	}
}

func verifyDomainCVEHierarchy(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	apacheService, cveResult := findDomainBaseCVE(results, "CVE-2026-24072")
	cvssResult, exploitResult := findDomainCVSSAndExploit(results, cveResult)
	attackComplexityResult := findDomainAttackComplexity(results, cvssResult)

	validateDomainCVEHierarchy(t, apacheService, cveResult, cvssResult, attackComplexityResult, exploitResult)

	_, cvePartial := findDomainBaseCVE(results, "CVE-2023-12345")
	cvssPartial, _ := findDomainCVSSAndExploit(results, cvePartial)
	if cvssPartial == nil || cvssPartial.Value != "MEDIUM / 5.3" {
		t.Errorf("expected CVSS score MEDIUM / 5.3, got %v", cvssPartial)
	}

	_, cveOnlySeverity := findDomainBaseCVE(results, "CVE-2023-12346")
	cvssSeverity, _ := findDomainCVSSAndExploit(results, cveOnlySeverity)
	if cvssSeverity == nil || cvssSeverity.Value != "LOW" {
		t.Errorf("expected CVSS score LOW, got %v", cvssSeverity)
	}

	_, cveOnlyBase := findDomainBaseCVE(results, "CVE-2023-12347")
	cvssBase, _ := findDomainCVSSAndExploit(results, cveOnlyBase)
	if cvssBase == nil || cvssBase.Value != "3.1" {
		t.Errorf("expected CVSS score 3.1, got %v", cvssBase)
	}
}

func findDomainBaseCVE(results []schema.ModuleResult, cveName string) (apacheService, cveResult *schema.ModuleResult) {
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeService && strings.Contains(res.Value, "Apache HTTP Server") {
			apacheService = res
		}
		if res.Type == constants.TypeCVE && res.Value == cveName {
			cveResult = res
		}
	}
	return apacheService, cveResult
}

func findDomainCVSSAndExploit(results []schema.ModuleResult, cveResult *schema.ModuleResult) (cvssResult, exploitResult *schema.ModuleResult) {
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeCVSS && cveResult != nil && res.Source != nil && res.Source.LocalID == cveResult.LocalID {
			cvssResult = res
		}
		if res.Type == constants.TypeThreatURL && cveResult != nil && res.Source != nil && res.Source.LocalID == cveResult.LocalID && strings.Contains(res.Value, "github.com") {
			exploitResult = res
		}
	}
	return cvssResult, exploitResult
}

func findDomainAttackComplexity(results []schema.ModuleResult, cvssResult *schema.ModuleResult) *schema.ModuleResult {
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeAttackComplexity && cvssResult != nil && res.Source != nil && res.Source.LocalID == cvssResult.LocalID {
			return res
		}
	}
	return nil
}

func validateDomainCVEHierarchy(t *testing.T, service, cveResult, cvssResult, attackComplexityResult, exploitResult *schema.ModuleResult) {
	t.Helper()
	if cveResult == nil || service == nil {
		t.Fatalf("CVE or Service not found")
	}
	if cveResult.Source.LocalID != service.LocalID {
		t.Errorf("CVE source mismatch: got %v, want %v", cveResult.Source.LocalID, service.LocalID)
	}

	if cvssResult == nil {
		t.Fatalf("CVSS result not found under CVE")
	}

	if attackComplexityResult != nil && attackComplexityResult.Source.LocalID != cvssResult.LocalID {
		t.Errorf("AttackComplexity source mismatch: got %v, want %v", attackComplexityResult.Source.LocalID, cvssResult.LocalID)
	}

	if exploitResult != nil && exploitResult.Source.LocalID != cveResult.LocalID {
		t.Errorf("Exploit URL source mismatch: got %v, want %v", exploitResult.Source.LocalID, cveResult.LocalID)
	}
}

func hasDNSTag(tags []string) bool {
	return slices.Contains(tags, constants.TagNS) || slices.Contains(tags, constants.TagMX) || slices.Contains(tags, constants.TagCNAME)
}

func isValidPureDomain(res *schema.ModuleResult) bool {
	if res.Type != constants.TypeDomain || res.Applied {
		return false
	}
	if hasDNSTag(res.Tags) || slices.Contains(res.Tags, constants.TagSPF) || slices.Contains(res.Tags, constants.TagWhoisServer) {
		return false
	}
	return true
}

func assertParsedDomains(t *testing.T, results []schema.ModuleResult, expectedCount int, expectExampleCom bool) {
	t.Helper()
	domainCount := 0
	foundExampleCom := false
	foundDep1 := false

	for i := range results {
		res := &results[i]
		if !isValidPureDomain(res) {
			continue
		}

		domainCount++
		if res.Value == "example.com" {
			foundExampleCom = true
		}
		if res.Value == "dep1.example.edu" {
			foundDep1 = true
		}
	}

	if len(results) == 0 {
		t.Errorf("expected parsed domains, got 0")
	}

	if domainCount != expectedCount {
		t.Errorf("expected exactly %d pure domains, got %d", expectedCount, domainCount)
	}
	if expectExampleCom && !foundExampleCom {
		t.Errorf("expected to find domain example.com")
	} else if !expectExampleCom && foundExampleCom {
		t.Errorf("expected NOT to find domain example.com")
	}
	if expectedCount == 5 && !foundDep1 {
		t.Errorf("expected to find domain dep1.example.edu")
	}
}

func assertTargetApplied(t *testing.T, results []schema.ModuleResult, targetValue string) {
	t.Helper()
	found := false
	for _, res := range results {
		if res.Applied && res.Value == targetValue {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find Applied: true for target %s", targetValue)
	}
}

func TestDomainEdgeCases(t *testing.T) {
	_ = t
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	val := "example.org"
	targetRef := &schema.EntityRef{Type: constants.TypeDomain, Value: val}

	addContact(exec, &netlasWhoisContact{Name: "", Organization: "", Email: ""}, constants.TypeWhoisRegistrant, targetRef, val, gen)

	w := &netlasWhoisDomain{
		Status:      []string{""},
		NameServers: []string{"invalid..ns", "valid.com"},
	}
	parseDomainWhois(exec, w, targetRef, val, gen)
}
