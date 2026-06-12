package netlas

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNetlasGetIP(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{testNameFullIP, "ip_responses.json"},
		{testNameEmptySource, "ip_responses_empty_source.json"},
		{testNameMinimal, "ip_responses_minimal.json"},
		{"EmptyWhois", "ip_responses_empty_whois.json"},
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

			input := schema.ModuleInput{
				Target:    schema.Entity{Type: constants.TypeIPv4, Value: "198.51.100.42"},
				Functions: []string{constants.FuncGetNetlasIP},
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
			requireValidSourceChaining(t, exec.Results, input.Target.Type, input.Target.Value)

			switch tt.name {
			case testNameFullIP:
				t.Run("General_Geo_ASN", func(t *testing.T) { assertIPResults(t, exec.Results) })
				t.Run("IoC_False_Positives", func(t *testing.T) { assertIPIoCFalsePositives(t, exec.Results) })
				t.Run("Whois_Net", func(t *testing.T) { assertIPWhoisNetResults(t, exec.Results) })
				t.Run("Parsed_Domains", func(t *testing.T) { assertIPDomains(t, exec.Results, 10, true) })
				t.Run("Contacts_Privacy", func(t *testing.T) { assertIPContacts(t, exec.Results) })
				t.Run("Software_Deduplication", func(t *testing.T) { assertIPSoftwareDeduplication(t, exec.Results) })
				t.Run("CVE_Hierarchy", func(t *testing.T) { verifyIPCVEHierarchy(t, exec.Results) })
				t.Run("Target_Applied", func(t *testing.T) { assertTargetApplied(t, exec.Results, testIP198) })
			case testNameEmptySource:
				assertIPDomains(t, exec.Results, 0, false)
			case testNameMinimal:
				assertHasResult(t, exec.Results, constants.TypeOrganization, "Atlantis ISP Ltd", "")
				assertHasResult(t, exec.Results, constants.TypeTag, constants.TagTorExit, "")
				assertHasResult(t, exec.Results, constants.TypeGeo, "Country: ZZ | Continent: Atlantis", "")
			case "EmptyWhois":
				assertIPDomains(t, exec.Results, 0, false)
			}
		})
	}
}

func assertIPResults(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	var foundGeo, foundVPN, foundASN, foundThreatURL bool
	for _, res := range results {
		switch res.Type {
		case constants.TypeGeo:
			if strings.Contains(res.Value, "Lost City") {
				foundGeo = true
			}
		case constants.TypeTag:
			if res.Value == constants.TagVPN {
				foundVPN = true
			}
		case constants.TypeASN:
			if res.Value == "AS64496" {
				foundASN = true
			}
		case constants.TypeThreatURL:
			if res.Value == "http://198.51.100.42:57734/bin.sh" {
				foundThreatURL = true
			}
		}
	}

	if !foundGeo {
		t.Errorf("expected to find geo data for Lost City")
	}
	if !foundVPN {
		t.Errorf("expected to find VPN tag")
	}
	if !foundASN {
		t.Errorf("expected to find ASN data AS64496")
	}
	if !foundThreatURL {
		t.Errorf("expected to find threat URL")
	}
}

func assertIPIoCFalsePositives(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	foundConfirmed := false
	foundPossible := false
	hasMalwareTag := false
	hasMaliciousTag := false
	hasPhishingTag := false

	for _, res := range results {
		if res.Type == constants.TypeInfo {
			if res.Value == "Confirmed False Positive: Message for true" {
				foundConfirmed = true
			}
			if res.Value == "Possible False Positive: Message for possible" {
				foundPossible = true
			}
		}

		if res.Type == constants.TypeIPv4 && res.Value == testIP198 {
			if slices.Contains(res.Tags, constants.TagMalware) {
				hasMalwareTag = true
			}
			if slices.Contains(res.Tags, constants.TagMalicious) {
				hasMaliciousTag = true
			}
			if slices.Contains(res.Tags, constants.TagPhishing) {
				hasPhishingTag = true
			}
		}
	}

	if !foundConfirmed {
		t.Errorf("expected to find Confirmed False Positive")
	}
	if !foundPossible {
		t.Errorf("expected to find Possible False Positive")
	}
	if hasMalwareTag {
		t.Errorf("expected IP NOT to be tagged with Malware due to false positive")
	}
	if hasMaliciousTag {
		t.Errorf("expected IP NOT to be tagged with Malicious due to false positive")
	}
	if !hasPhishingTag {
		t.Errorf("expected Target to have phishing tag (per-tag latest has no FP)")
	}
}

func assertIPDomains(t *testing.T, results []schema.ModuleResult, expectedCount int, expectExampleCom bool) {
	t.Helper()
	domainCount := 0
	foundExampleCom := false

	for _, res := range results {
		if res.Type != constants.TypeDomain && res.Type != constants.TypeSubdomain {
			continue
		}
		if res.Applied {
			continue
		}

		domainCount++
		if res.Value == "example.edu" {
			foundExampleCom = true
		}
	}

	if domainCount != expectedCount {
		t.Errorf("expected exactly %d pure domains, got %d", expectedCount, domainCount)
	}
	if expectExampleCom && !foundExampleCom {
		t.Errorf("expected to find domain example.edu")
	} else if !expectExampleCom && foundExampleCom {
		t.Errorf("expected NOT to find domain example.edu")
	}
}

func assertIPWhoisNetResults(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	var foundDesc, foundAddress, foundNetwork bool
	for _, res := range results {
		switch res.Type {
		case constants.TypeDescription:
			if strings.Contains(res.Value, "Oceania Depths Internal Network") {
				foundDesc = true
			}
		case constants.TypeAddress:
			if strings.Contains(res.Value, "1 Underwater Blvd, Lost City, DW 00000, ORG-OCEAN-NULL, Atlantis 00000, ZZ") {
				foundAddress = true
			}
		case constants.TypeNetwork:
			if strings.Contains(res.Value, "OCEAN-NET, NEMO-NULL") {
				foundNetwork = true
			}
		}
	}

	if !foundDesc {
		t.Errorf("expected to find description")
	}
	if !foundAddress {
		t.Errorf("expected to find address 1 Underwater Blvd")
	}
	if !foundNetwork {
		t.Errorf("expected to find network identifier with name and handle")
	}

	assertIPWhoisASNResults(t, results)
}

func assertIPWhoisASNResults(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	assertHasResult(t, results, constants.TypeOrganization, "OCEAN-AS", "")
	assertHasResult(t, results, constants.TypeCIDR, "198.51.100.0/24", "")
	assertHasResult(t, results, constants.TypeInfo, "Registry: NULL", "ASN Registry")
	assertHasResult(t, results, constants.TypeDate, "Updated Date: 2015-08-20", "Whois Record (Updated)")
}

func assertHasResult(t *testing.T, results []schema.ModuleResult, typ, value, ctx string) {
	t.Helper()
	for _, res := range results {
		if res.Type == typ && res.Value == value {
			if ctx == "" || res.Context == ctx {
				return
			}
		}
	}
	t.Errorf("expected to find %s with value %s (context %s)", typ, value, ctx)
}

func assertIPContacts(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	var foundPerson, foundEmail bool
	emailCount := 0
	phoneCount := 0
	var phones []string

	for _, res := range results {
		switch res.Type {
		case constants.TypePerson:
			if res.Value == "Captain Nemo" {
				foundPerson = true
			}
		case constants.TypeEmail:
			emailCount++
			if res.Value == "abuse@ocean-net.example.com" {
				foundEmail = true
			}
		case constants.TypePhone:
			phoneCount++
			phones = append(phones, res.Value)
		}
	}

	if !foundPerson {
		t.Errorf("expected to find person Captain Nemo")
	}
	if !foundEmail {
		t.Errorf("expected to find email abuse@ocean-net.example.com")
	}
	if emailCount != 1 {
		t.Errorf("expected exactly 1 email total (deduplicated, invalid dropped), got %d", emailCount)
	}
	if phoneCount != 2 {
		t.Errorf("expected exactly 2 phones (deduplicated and zeros removed), got %d: %v", phoneCount, phones)
	}
}

func assertIPSoftwareDeduplication(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	nginxCount := 0
	for _, res := range results {
		if res.Type == constants.TypeService {
			if strings.Contains(res.Value, "Nginx") && strings.Contains(res.Value, "1.18.0") {
				nginxCount++
			}
		}
	}
	if nginxCount != 1 {
		t.Errorf("expected exactly 1 Nginx 1.18.0 service due to CPE deduplication, got %d", nginxCount)
	}
}

func verifyIPCVEHierarchy(t *testing.T, results []schema.ModuleResult) {
	t.Helper()
	sshService, sshCPE, cveResult := findBaseCVE(results)
	cvssResult, exploitResult := findCVSSAndExploit(results, cveResult)
	attackComplexityResult := findAttackComplexity(results, cvssResult)

	validateIPCVEHierarchy(t, sshService, sshCPE, cveResult, cvssResult, attackComplexityResult, exploitResult)
}

func findBaseCVE(results []schema.ModuleResult) (sshService, sshCPE, cveResult *schema.ModuleResult) {
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeService && strings.Contains(res.Value, "OpenSSH") {
			sshService = res
		}
		if res.Type == constants.TypeCPE && strings.Contains(res.Value, "openssh") {
			sshCPE = res
		}
		if res.Type == constants.TypeCVE && res.Value == "CVE-2018-15473" {
			cveResult = res
		}
	}
	return sshService, sshCPE, cveResult
}

func findCVSSAndExploit(results []schema.ModuleResult, cveResult *schema.ModuleResult) (cvssResult, exploitResult *schema.ModuleResult) {
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeCVSS && cveResult != nil && res.Source != nil && res.Source.LocalID == cveResult.LocalID {
			cvssResult = res
		}
		if res.Type == constants.TypeExploit && cveResult != nil && res.Source != nil && res.Source.LocalID == cveResult.LocalID {
			exploitResult = res
		}
	}
	return cvssResult, exploitResult
}

func findAttackComplexity(results []schema.ModuleResult, cvssResult *schema.ModuleResult) *schema.ModuleResult {
	var attackComplexityResult *schema.ModuleResult
	for i := range results {
		res := &results[i]
		if res.Type == constants.TypeAttackComplexity && cvssResult != nil && res.Source != nil && res.Source.LocalID == cvssResult.LocalID {
			attackComplexityResult = res
		}
	}
	return attackComplexityResult
}

func validateIPCVEHierarchy(t *testing.T, service, cpe, cveResult, cvssResult, attackComplexityResult, exploitResult *schema.ModuleResult) {
	t.Helper()
	if cveResult == nil || cpe == nil || service == nil {
		t.Fatalf("Service, CPE, or CVE not found")
	}
	if cpe.Source.LocalID != service.LocalID {
		t.Errorf("CPE source mismatch: got %v, want %v (Service)", cpe.Source.LocalID, service.LocalID)
	}
	if cveResult.Source.LocalID != cpe.LocalID {
		t.Errorf("CVE source mismatch: got %v, want %v (CPE)", cveResult.Source.LocalID, cpe.LocalID)
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

func TestResolveWhoisOrg(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		name     string
		resp     *netlasWhoisIPNet
		rootOrg  string
		expected string
	}{
		{"RootOrg", &netlasWhoisIPNet{Organization: "Org-Root", Name: "Net-Root", Description: "Primary block", Handle: "HDL-ROOT"}, "RootOrgName", "RootOrgName"},
		{"Organization", &netlasWhoisIPNet{Organization: "Org-Only", Name: "Net-Org", Description: "Secondary block", Handle: "HDL-ORG"}, "", "Org-Only"},
		{"Name", &netlasWhoisIPNet{Name: "Net-Name", Description: "Tertiary block", Handle: "HDL-NET"}, "", "Net-Name"},
		{"Description", &netlasWhoisIPNet{Description: "Fallback block", Handle: "HDL-DESC"}, "", "Fallback block"},
		{"Handle", &netlasWhoisIPNet{Handle: "HDL-ONLY"}, "", "HDL-ONLY"},
		{"Empty", &netlasWhoisIPNet{}, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := modutil.NewExecution("test")
			ref := &schema.EntityRef{Type: constants.TypeIPv4, Value: "192.0.2.50"}
			_, orgName := resolveWhoisOrg(&exec, tt.resp, tt.rootOrg, ref, gen)

			if tt.expected != orgName {
				t.Errorf("expected orgName %s, got %s", tt.expected, orgName)
			}

			if tt.expected == "" {
				if len(exec.Results) != 0 {
					t.Errorf("expected 0 results, got %d", len(exec.Results))
				}
			} else {
				if len(exec.Results) != 1 {
					t.Errorf("expected 1 result, got %d", len(exec.Results))
				} else if exec.Results[0].Value != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, exec.Results[0].Value)
				}
			}
		})
	}
}

func TestParseIPWhoisNil(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	ref := &schema.EntityRef{Type: constants.TypeIP, Value: "192.0.2.51"}
	parseIPWhois(exec, nil, "root", ref, gen)
	if len(exec.Results) > 0 {
		t.Errorf("expected no results for nil whois")
	}
}

func TestAddSystemTagToNodeNil(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	addSystemTagToNode(exec, nil, constants.TagCVE, gen)
	if len(exec.Results) > 0 {
		t.Errorf("expected no results for nil targetRef")
	}
}

func TestParseWhoisASN(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	ref := &schema.EntityRef{Type: constants.TypeIP, Value: "192.0.2.52"}

	parseWhoisASN(exec, nil, ref, gen)

	asn := &netlasWhoisASN{Number: []string{""}}
	parseWhoisASN(exec, asn, ref, gen)

	asn = &netlasWhoisASN{Number: []string{"invalid"}}
	parseWhoisASN(exec, asn, ref, gen)

	if len(exec.Results) > 0 {
		t.Errorf("expected no results")
	}
}

func TestFormatWhoisNetAddress(t *testing.T) {
	tests := []struct {
		name     string
		net      *netlasWhoisIPNet
		orgName  string
		expected string
	}{
		{
			name: "Both State and Postal",
			net: &netlasWhoisIPNet{
				State:      "NY",
				PostalCode: "10001",
			},
			expected: "NY 10001",
		},
		{
			name: "State Only",
			net: &netlasWhoisIPNet{
				State: "CA",
			},
			expected: "CA",
		},
		{
			name: "Postal Only",
			net: &netlasWhoisIPNet{
				PostalCode: "90210",
			},
			expected: "90210",
		},
		{
			name: "With Address and City",
			net: &netlasWhoisIPNet{
				Address:    "123 Main St",
				City:       "Springfield",
				State:      "IL",
				PostalCode: "62701",
				Country:    "US",
			},
			expected: "123 Main St, Springfield, IL 62701, US",
		},
		{
			name:     "Empty",
			net:      &netlasWhoisIPNet{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatWhoisNetAddress(tt.net, tt.orgName)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestParseWhoisNetCIDRErrors(t *testing.T) {
	exec := &schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	orgRef := &schema.EntityRef{Type: constants.TypeOrganization, Value: "Test Org"}

	net := &netlasWhoisIPNet{
		CIDR: []string{
			"",
			"INVALID",
			"192.168.1.1",
			"1.2.3.4/abc",
			"1.2.3.4/-1",
			"1.2.3.4/130",
		},
	}

	parseWhoisNet(exec, net, "", orgRef, false, nil, gen)

	for _, res := range exec.Results {
		if res.Type == constants.TypeCIDR {
			t.Errorf("expected no CIDR results, got %v", res.Value)
		}
	}
}

func TestParseIoC_Synthetic(t *testing.T) {
	tests := []struct {
		name          string
		iocJSON       string
		expectTags    []string
		notExpectTags []string
	}{
		{
			name: "PerTag_FP_Only_Cancels_Own_Tag",
			iocJSON: `[
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":63.0}, "fp":{"alarm":"true"}, "tags":["malware"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":63.0}, "fp":{"alarm":"false"}, "tags":["c2"]},
                {"@timestamp":"2024-12-12T00:00Z", "score":{"total":56.0}, "fp":{"alarm":"false"}, "tags":["phishing"]}
            ]`,
			expectTags:    []string{constants.TagC2, constants.TagPhishing},
			notExpectTags: []string{constants.TagMalware},
		},
		{
			name: "PerTag_Multiple_Same_Day_No_FP",
			iocJSON: `[
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":63.0}, "fp":{"alarm":"false"}, "url":"http://a", "tags":["malware", "suspicious"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":70.0}, "fp":{"alarm":"false"}, "url":"http://b", "tags":["ransomware"]},
                {"@timestamp":"2023-11-18T00:00Z", "score":{"total":60.0}, "fp":{"alarm":"false"}, "tags":["phishing"]}
            ]`,
			expectTags:    []string{constants.TagMalware, constants.TagSuspicious, constants.TagRansomware, constants.TagPhishing},
			notExpectTags: []string{},
		},
		{
			name: "PerTag_Low_Score_Blocks_Tag",
			iocJSON: `[
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":10.0}, "fp":{"alarm":"false"}, "tags":["miner"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":80.0}, "fp":{"alarm":"false"}, "tags":["botnet"]}
            ]`,
			expectTags:    []string{constants.TagBotnet},
			notExpectTags: []string{constants.TagMiner},
		},
		{
			name: "PerTag_Newer_FP_Overrides_Older_Confirmed",
			iocJSON: `[
                {"@timestamp":"2024-01-01T00:00Z", "score":{"total":80.0}, "fp":{"alarm":"false"}, "tags":["malware"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":60.0}, "fp":{"alarm":"true"}, "tags":["malware"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":60.0}, "fp":{"alarm":"false"}, "tags":["c2"]}
            ]`,
			expectTags:    []string{constants.TagC2},
			notExpectTags: []string{constants.TagMalware},
		},
		{
			name: "PerTag_Same_Day_Multiple_Records_Same_Tag",
			iocJSON: `[
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":10.0}, "fp":{"alarm":"false"}, "tags":["c2"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":80.0}, "fp":{"alarm":"false"}, "tags":["c2"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":60.0}, "fp":{"alarm":"false"}, "tags":["malware"]},
                {"@timestamp":"2026-05-16T00:00Z", "score":{"total":60.0}, "fp":{"alarm":"true"}, "tags":["malware"]}
            ]`,
			expectTags:    []string{constants.TagC2},
			notExpectTags: []string{constants.TagMalware},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			respJSON := fmt.Sprintf(`{"ip":"198.51.100.42","ioc":%s}`, tt.iocJSON)
			server := setupMockServer(t, []byte(respJSON))
			defer server.Close()
			originalURL := netlasAPIBaseURL
			netlasAPIBaseURL = server.URL
			defer func() { netlasAPIBaseURL = originalURL }()

			m := &netlasModule{apiKey: testAPIKey}
			input := schema.ModuleInput{
				Target:    schema.Entity{Type: constants.TypeIPv4, Value: testIP198},
				Functions: []string{constants.FuncGetNetlasIP},
			}

			out, err := m.Exec(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var targetTags []string
			for _, res := range out.Executions[0].Results {
				if res.Type == constants.TypeIPv4 && res.Value == testIP198 {
					targetTags = append(targetTags, res.Tags...)
				}
			}

			for _, expectedTag := range tt.expectTags {
				if !slices.Contains(targetTags, expectedTag) {
					t.Errorf("expected Target to have tag %s", expectedTag)
				}
			}
			for _, notExpectedTag := range tt.notExpectTags {
				if slices.Contains(targetTags, notExpectedTag) {
					t.Errorf("expected Target NOT to have tag %s", notExpectedTag)
				}
			}
		})
	}
}
