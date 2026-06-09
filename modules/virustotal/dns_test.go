package virustotal

import (
	"encoding/json"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func parseDNSRecordFromFixture(t *testing.T, target string, source *schema.EntityRef, rec map[string]any) []schema.ModuleResult {
	t.Helper()

	mod := &module{}
	exec := schema.ModuleExecution{}
	gen := modutil.NewLocalIDGenerator()
	mod.parseDNSRecord(rec, target, source, &exec, gen)

	return exec.Results
}

func assertFixtureResultSource(t *testing.T, source, got *schema.EntityRef) {
	t.Helper()

	if got == nil || got.Type != source.Type || got.Value != source.Value {
		t.Fatalf("expected source %s, got %s", describeSource(source), describeSource(got))
	}
}

func loadFixturePayload(t *testing.T, fileName string) map[string]any {
	t.Helper()

	var payload map[string]any
	if err := json.Unmarshal([]byte(loadVTFixture(t, fileName)), &payload); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", fileName, err)
	}

	return payload
}

func loadFixtureDNSRecords(t *testing.T, fileName, itemID string) []any {
	t.Helper()

	payload := loadFixturePayload(t, fileName)
	data := payload["data"]

	if records := loadRootFixtureDNSRecords(data, itemID); records != nil {
		return records
	}
	if records := loadListFixtureDNSRecords(data, itemID); records != nil {
		return records
	}

	t.Fatalf("missing fixture dns records file=%s item=%s", fileName, itemID)
	return nil
}

func loadRootFixtureDNSRecords(data any, itemID string) []any {
	item, ok := data.(map[string]any)
	if !ok {
		return nil
	}

	fixtureID, ok := item["id"].(string)
	if !ok {
		return nil
	}
	if itemID != "" && fixtureID != itemID {
		return nil
	}

	attributes, ok := item["attributes"].(map[string]any)
	if !ok {
		return nil
	}
	records, ok := attributes["last_dns_records"].([]any)
	if !ok {
		return nil
	}

	return records
}

func loadListFixtureDNSRecords(data any, itemID string) []any {
	items, ok := data.([]any)
	if !ok {
		return nil
	}

	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		fixtureID, ok := item["id"].(string)
		if !ok || fixtureID != itemID {
			continue
		}

		attributes, ok := item["attributes"].(map[string]any)
		if !ok {
			return nil
		}
		records, ok := attributes["last_dns_records"].([]any)
		if !ok {
			return nil
		}

		return records
	}

	return nil
}

func findFixtureDNSRecord(t *testing.T, records []any, recordType string, predicate func(map[string]any) bool) map[string]any {
	t.Helper()

	for _, rawRecord := range records {
		record, ok := rawRecord.(map[string]any)
		if !ok {
			continue
		}
		currentType, ok := record["type"].(string)
		if !ok || currentType != recordType {
			continue
		}
		if predicate == nil || predicate(record) {
			return record
		}
	}

	t.Fatalf("missing fixture record type=%s", recordType)
	return nil
}

func loadFixtureDNSRecord(t *testing.T, fileName, itemID, recordType string, predicate func(map[string]any) bool) map[string]any {
	t.Helper()

	records := loadFixtureDNSRecords(t, fileName, itemID)
	return findFixtureDNSRecord(t, records, recordType, predicate)
}

func TestParseDNSRecordMXAddsPropertyAndSkipsSelfReferentialHost(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureMailSubdomain, "MX", func(record map[string]any) bool {
		value, ok := record[constants.KeyValue].(string)
		return ok && value == fixtureMailSubdomain
	})
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureMailSubdomain}
	results := parseDNSRecordFromFixture(t, fixtureMailSubdomain, source, rec)

	mxProp := requireResult(t, results, "mx property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeMX && result.Category == constants.CategoryProperty && result.Value == "5 "+fixtureMailSubdomain
	})
	assertFixtureResultSource(t, source, mxProp.Source)

	for _, res := range results {
		if res.Type == constants.TypeSubdomain && res.Category == constants.CategoryNode && res.Value == fixtureMailSubdomain && slices.Contains(res.Tags, constants.TagMX) {
			t.Fatal("expected self-referential MX host to NOT be emitted as a node")
		}
	}
}

func TestParseDNSRecordNSYieldsNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureAPISubdomain, "NS", nil)
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureAPISubdomain}
	results := parseDNSRecordFromFixture(t, fixtureAPISubdomain, source, rec)

	nsResult := requireResult(t, results, "ns node", func(result schema.ModuleResult) bool {
		hasNSTag := slices.Contains(result.Tags, constants.TagNS)
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == "ns1.target-example.com" && hasNSTag
	})
	assertFixtureResultSource(t, source, nsResult.Source)
}

func TestParseDNSRecordSOAAddsPropertyAndPrimaryNSNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "domain_page1.json", fixtureDomainTarget, "SOA", nil)
	source := &schema.EntityRef{Type: constants.TypeDomain, Value: fixtureDomainTarget}
	results := parseDNSRecordFromFixture(t, fixtureDomainTarget, source, rec)

	soaProp := requireResult(t, results, "soa property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSOA && result.Category == constants.CategoryProperty && result.Value == "ns1-39.example-dns.com. exampledns-hostmaster.target-example.com. 1 3600 300 2419200 300"
	})
	assertFixtureResultSource(t, source, soaProp.Source)

	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaProp.Value}

	nsResult := requireResult(t, results, "primary ns node", func(result schema.ModuleResult) bool {
		hasNSTag := slices.Contains(result.Tags, constants.TagNS)
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == "ns1-39.example-dns.com" && hasNSTag
	})
	assertFixtureResultSource(t, soaRef, nsResult.Source)

	emailResult := requireResult(t, results, "responsible email node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeEmail && result.Category == constants.CategoryNode && result.Value == "exampledns-hostmaster@target-example.com"
	})
	assertFixtureResultSource(t, soaRef, emailResult.Source)
}

func TestParseDNSRecordCAAAddsAuthorityNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureMailSubdomain, "CAA", func(record map[string]any) bool {
		value, ok := record[constants.KeyValue].(string)
		return ok && value == "mail-ca.example.org"
	})
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureMailSubdomain}
	results := parseDNSRecordFromFixture(t, fixtureMailSubdomain, source, rec)

	for _, r := range results {
		t.Logf("Result: %+v", r)
	}

	caaProp := requireResult(t, results, "caa property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCAA && result.Category == constants.CategoryProperty && result.Value == `0 issue "mail-ca.example.org"`
	})
	caaRef := &schema.EntityRef{Type: constants.TypeCAA, Value: caaProp.Value}

	authority := requireResult(t, results, "cert authority node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == "mail-ca.example.org" && slices.Contains(result.Tags, constants.TagCAA)
	})
	assertFixtureResultSource(t, caaRef, authority.Source)
}

func TestParseDNSRecordSRVAddsPropertyAndHostNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "domain_page1.json", fixtureDomainTarget, "SRV", nil)
	source := &schema.EntityRef{Type: constants.TypeDomain, Value: fixtureDomainTarget}
	results := parseDNSRecordFromFixture(t, fixtureDomainTarget, source, rec)

	srvProp := requireResult(t, results, "srv property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSRV && result.Category == constants.CategoryProperty && result.Value == "10 50 5060 sip.example.com."
	})
	assertFixtureResultSource(t, source, srvProp.Source)

	srvRef := &schema.EntityRef{Type: constants.TypeSRV, Value: srvProp.Value}

	srvHost := requireResult(t, results, "srv node", func(result schema.ModuleResult) bool {
		hasSRVTag := slices.Contains(result.Tags, constants.TagSRV)
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == "sip.example.com" && hasSRVTag
	})
	assertFixtureResultSource(t, srvRef, srvHost.Source)
}

func TestParseDNSRecordSelfReferentialSkipped(t *testing.T) {
	mod := &module{}
	exec := schema.ModuleExecution{}

	tests := []struct {
		typ    string
		val    string
		rec    map[string]any
		name   string
		target string
	}{
		{"CNAME", "cname.vt.example.com", map[string]any{}, "test_CNAME", "cname.vt.example.com"},
		{"NS", "ns.vt.example.com", map[string]any{}, "test_NS", "ns.vt.example.com"},
		{"SOA", "soa.vt.example.com", map[string]any{"rname": "admin.vt.example.com", constants.KeySerial: 123}, "test_SOA", "soa.vt.example.com"},
		{"CAA", "caa.vt.example.com", map[string]any{constants.TypeTag: constants.DNSIssue}, "test_CAA", "caa.vt.example.com"},
		{"SRV", "10 5060 srv.vt.example.com", map[string]any{constants.KeyPriority: 10}, "test_SRV", "srv.vt.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rec[constants.KeyType] = tt.typ
			tt.rec[constants.KeyValue] = tt.val
			gen := modutil.NewLocalIDGenerator()
			mod.parseDNSRecord(tt.rec, tt.target, nil, &exec, gen)
			for _, res := range exec.Results {
				if res.Category == constants.CategoryNode && res.Value == tt.target {
					t.Fatalf("expected self-referential %s host to NOT be emitted as a node", tt.name)
				}
			}
			exec.Results = nil
		})
	}
}

func TestParseDNSRecordAInvalidIP(t *testing.T) {
	rec := map[string]any{
		constants.KeyType:  "A",
		constants.KeyValue: "999.999.999.999",
	}
	target := "invalid-ip.target.example.net"
	results := parseDNSRecordFromFixture(t, target, nil, rec)

	if len(results) != 0 {
		t.Fatalf("expected 0 results for invalid IP, got %d", len(results))
	}
}

func TestAppendVTCAAResults(t *testing.T) {
	m := &module{}
	src := &schema.EntityRef{Type: constants.TypeSubdomain, Value: "gamma.delta.epsilon.example.org", LocalID: 1}

	tests := []struct {
		rec           map[string]any
		name          string
		expectedValue string
		expectedCount int
	}{
		{
			rec:           map[string]any{},
			name:          "empty map",
			expectedValue: "",
			expectedCount: 0,
		},
		{
			rec:           map[string]any{constants.TypeTag: constants.DNSIssue, constants.KeyValue: "issuer.example.net"},
			name:          "missing flag, valid tag and value",
			expectedValue: "0 issue \"issuer.example.net\"",
			expectedCount: 2,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 128, constants.TypeTag: constants.DNSIssueWild, constants.KeyValue: "wildcard.example.com"},
			name:          "valid flag, tag and value",
			expectedValue: "128 issuewild \"wildcard.example.com\"",
			expectedCount: 2,
		},
		{
			rec:           map[string]any{constants.KeyFlag: float64(0), constants.KeyValue: "raw-certificate-value.example.org"},
			name:          "valid flag and value, missing tag",
			expectedValue: "raw-certificate-value.example.org",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIodef, constants.KeyValue: "   \t   "},
			name:          "value is only spaces",
			expectedValue: "",
			expectedCount: 0,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: 123, constants.KeyValue: "fallback.example.net"},
			name:          "invalid tag type",
			expectedValue: "fallback.example.net",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIssue, constants.KeyValue: 12345},
			name:          "invalid value type",
			expectedValue: "",
			expectedCount: 0,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIssue, constants.KeyValue: "target.caa.example.org"},
			name:          "issue with same domain as target",
			expectedValue: "0 issue \"target.caa.example.org\"",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIssue, constants.KeyValue: "not_a_valid_domain_!@#$"},
			name:          "issue with invalid authority domain",
			expectedValue: "0 issue \"not_a_valid_domain_!@#$\"",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIodef, constants.KeyValue: "mailto:abuse@example.org"},
			name:          "iodef with valid mailto",
			expectedValue: "0 iodef \"mailto:abuse@example.org\"",
			expectedCount: 2,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIodef, constants.KeyValue: "mailto:"},
			name:          "iodef with empty mailto",
			expectedValue: "0 iodef \"mailto:\"",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIodef, constants.KeyValue: "http://example.org/caa"},
			name:          "iodef with missing email (http)",
			expectedValue: "0 iodef \"http://example.org/caa\"",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIodef, constants.KeyValue: "mailto:not-an-email"},
			name:          "iodef with invalid email",
			expectedValue: "0 iodef \"mailto:not-an-email\"",
			expectedCount: 1,
		},
		{
			rec:           map[string]any{constants.KeyFlag: 0, constants.TypeTag: constants.DNSIssue, constants.KeyValue: ";"},
			name:          "issue with empty authority",
			expectedValue: "0 issue \";\"",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := modutil.NewLocalIDGenerator()
			exec := &schema.ModuleExecution{}
			m.appendVTCAAResults(exec, "target.caa.example.org", src, tt.rec, gen)

			if len(exec.Results) != tt.expectedCount {
				t.Fatalf("expected %d results, got %d", tt.expectedCount, len(exec.Results))
			}

			if tt.expectedCount > 0 {
				res := exec.Results[0]
				if res.Type != constants.TypeCAA {
					t.Errorf("expected Type %q, got %q", constants.TypeCAA, res.Type)
				}
				if res.Value != tt.expectedValue {
					t.Errorf("expected Value %q, got %q", tt.expectedValue, res.Value)
				}
			}
		})
	}
}

func TestParseDNSRecord_EdgeCases(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{}
	src := &schema.EntityRef{Type: constants.TypeSubdomain, Value: "sub0.example.net", LocalID: gen.NextID()}

	m.parseDNSRecord(map[string]any{constants.KeyValue: "127.0.0.100"}, "sub0.example.net", src, exec, gen)
	m.parseDNSRecord(map[string]any{constants.KeyType: "A"}, "sub0.example.net", src, exec, gen)
	m.parseDNSRecord(map[string]any{constants.KeyType: "   ", constants.KeyValue: "127.0.0.101"}, "sub0.example.net", src, exec, gen)
	m.parseDNSRecord(map[string]any{constants.KeyType: "A", constants.KeyValue: "   "}, "sub0.example.net", src, exec, gen)

	if len(exec.Results) != 0 {
		t.Errorf("expected 0 results for missing/empty fields, got %d", len(exec.Results))
	}

	m.parseDNSRecord(map[string]any{constants.KeyType: "UNKNOWN_TYPE_XYZ", constants.KeyValue: "fallback_value_123"}, "sub0.example.net", src, exec, gen)
	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 result for unknown type, got %d", len(exec.Results))
	}
	if exec.Results[0].Type != "unknown_type_xyz" || exec.Results[0].Value != "fallback_value_123" {
		t.Errorf("unexpected fallback result: %+v", exec.Results[0])
	}
}

func TestAppendVT_EdgeCases(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec1 := &schema.ModuleExecution{}
	m.appendVTCNAMEResult(exec1, "sub1.example.net", nil, "invalid cname 1!", gen)
	if len(exec1.Results) != 0 {
		t.Errorf("expected 0 results for invalid CNAME, got %d", len(exec1.Results))
	}

	exec2 := &schema.ModuleExecution{}
	m.appendVTMXResults(exec2, "sub2.example.net", nil, map[string]any{constants.KeyPriority: 10}, "invalid mx 2!", gen)
	foundMXNode := false
	for _, res := range exec2.Results {
		if res.Category == constants.CategoryNode {
			foundMXNode = true
		}
	}
	if foundMXNode {
		t.Error("expected no node result for invalid MX")
	}

	exec3 := &schema.ModuleExecution{}
	m.appendVTNSResult(exec3, "sub3.example.net", nil, "invalid ns 3!", gen)
	if len(exec3.Results) != 0 {
		t.Errorf("expected 0 results for invalid NS, got %d", len(exec3.Results))
	}

	exec4 := &schema.ModuleExecution{}
	m.appendVTSRVResults(exec4, "sub6.example.net", nil, map[string]any{constants.KeyPriority: 10}, "0 0 80 invalid srv 6!", gen)
	foundSRVNode := false
	for _, res := range exec4.Results {
		if res.Category == constants.CategoryNode {
			foundSRVNode = true
		}
	}
	if foundSRVNode {
		t.Error("expected no node result for invalid SRV")
	}

	exec5 := &schema.ModuleExecution{}
	m.appendVTSRVResults(exec5, "example.net", nil, map[string]any{constants.KeyPriority: 10}, "0 80 example.net", gen)
	foundSRVNode2 := false
	for _, res := range exec5.Results {
		if res.Category == constants.CategoryNode {
			foundSRVNode2 = true
		}
	}
	if foundSRVNode2 {
		t.Error("expected no node result for self-referential SRV")
	}
}

func TestAppendVTSOAResults_EdgeCases(t *testing.T) {
	m := &module{}
	gen := modutil.NewLocalIDGenerator()

	exec1 := &schema.ModuleExecution{}
	m.appendVTSOAResults(exec1, "sub4.example.net", nil, map[string]any{}, gen)
	if len(exec1.Results) != 0 {
		t.Errorf("expected 0 results for empty SOA, got %d", len(exec1.Results))
	}

	exec2 := &schema.ModuleExecution{}
	m.appendVTSOAResults(exec2, "admin@sub4.example.net", nil, map[string]any{
		"rname":             "admin.sub4.example.net",
		constants.KeySerial: 12345,
	}, gen)
	foundEmailNode := false
	for _, res := range exec2.Results {
		if res.Category == constants.CategoryNode && res.Type == constants.TypeEmail {
			foundEmailNode = true
		}
	}
	if foundEmailNode {
		t.Error("expected no email node result for self-referential SOA email")
	}
}

func TestEnsureFQDN_EdgeCases(t *testing.T) {
	if res := ensureFQDN(""); res != "" {
		t.Errorf("expected empty string, got %q", res)
	}
	if res := ensureFQDN("fqdn.example.net."); res != "fqdn.example.net." {
		t.Errorf("expected fqdn.example.net., got %q", res)
	}
}

func TestBuildVTSPFEntityResult_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	_, ok1 := buildVTSPFEntityResult(nil, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityIP4, Value: "300.400.500.600"}, "sub5.example.net", gen)
	if ok1 {
		t.Error("expected false for invalid IP")
	}

	_, ok2 := buildVTSPFEntityResult(nil, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityDomain, Value: "invalid spf 5!"}, "sub5.example.net", gen)
	if ok2 {
		t.Error("expected false for invalid Domain")
	}

	_, ok3 := buildVTSPFEntityResult(nil, dnsutils.SPFEntity{Kind: dnsutils.SPFEntityDomain, Value: "sub5.example.net"}, "sub5.example.net", gen)
	if ok3 {
		t.Error("expected false for self-referential Domain")
	}

	_, ok4 := buildVTSPFEntityResult(nil, dnsutils.SPFEntity{Kind: 1337, Value: "something"}, "sub5.example.net", gen)
	if ok4 {
		t.Error("expected false for unknown Kind")
	}
}
