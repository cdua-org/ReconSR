package virustotal

import (
	"encoding/json"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func parseDNSRecordFromFixture(t *testing.T, target string, source *schema.EntityRef, rec map[string]any) []schema.ModuleResult {
	t.Helper()

	mod := &module{}
	exec := schema.ModuleExecution{}
	mod.parseDNSRecord(rec, target, source, &exec)

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

func TestParseDNSRecordMXAddsPropertyAndHostNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureMailSubdomain, "MX", func(record map[string]any) bool {
		value, ok := record["value"].(string)
		return ok && value == fixtureMailSubdomain
	})
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureMailSubdomain}
	results := parseDNSRecordFromFixture(t, fixtureMailSubdomain, source, rec)

	requireResult(t, results, "mx property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeMX && result.Category == constants.CategoryProperty && result.Value == "5 "+fixtureMailSubdomain
	})

	mxHost := requireResult(t, results, "mx host node", func(result schema.ModuleResult) bool {
		hasMXTag := slices.Contains(result.Tags, constants.TagMX)
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == fixtureMailSubdomain && hasMXTag
	})
	assertFixtureResultSource(t, source, mxHost.Source)
}

func TestParseDNSRecordNSYieldsNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureAPISubdomain, "NS", nil)
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureAPISubdomain}
	results := parseDNSRecordFromFixture(t, fixtureAPISubdomain, source, rec)

	nsResult := requireResult(t, results, "ns node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeNS && result.Category == constants.CategoryNode && result.Value == "ns1.target-example.com"
	})
	assertFixtureResultSource(t, source, nsResult.Source)
}

func TestParseDNSRecordSOAAddsPropertyAndPrimaryNSNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "domain_page1.json", fixtureDomainTarget, "SOA", nil)
	source := &schema.EntityRef{Type: constants.TypeDomain, Value: fixtureDomainTarget}
	results := parseDNSRecordFromFixture(t, fixtureDomainTarget, source, rec)

	requireResult(t, results, "soa property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSOA && result.Category == constants.CategoryProperty && result.Value == "ns1-39.example-dns.com. exampledns-hostmaster.target-example.com. 1 3600 300 2419200 300"
	})

	nsResult := requireResult(t, results, "soa primary ns node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeNS && result.Category == constants.CategoryNode && result.Value == "ns1-39.example-dns.com"
	})
	assertFixtureResultSource(t, source, nsResult.Source)
}

func TestParseDNSRecordCAAAddsAuthorityNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "subdomains_page1.json", fixtureMailSubdomain, "CAA", func(record map[string]any) bool {
		value, ok := record["value"].(string)
		return ok && value == "mail-ca.example.org"
	})
	source := &schema.EntityRef{Type: constants.TypeSubdomain, Value: fixtureMailSubdomain}
	results := parseDNSRecordFromFixture(t, fixtureMailSubdomain, source, rec)

	requireResult(t, results, "caa property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCAA && result.Category == constants.CategoryProperty && result.Value == `0 issue "mail-ca.example.org"`
	})

	authority := requireResult(t, results, "cert authority node", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeCertAuthority && result.Category == constants.CategoryNode && result.Value == "mail-ca.example.org"
	})
	assertFixtureResultSource(t, source, authority.Source)
}

func TestParseDNSRecordSRVAddsPropertyAndHostNode(t *testing.T) {
	rec := loadFixtureDNSRecord(t, "domain_page1.json", fixtureDomainTarget, "SRV", nil)
	source := &schema.EntityRef{Type: constants.TypeDomain, Value: fixtureDomainTarget}
	results := parseDNSRecordFromFixture(t, fixtureDomainTarget, source, rec)

	requireResult(t, results, "srv property", func(result schema.ModuleResult) bool {
		return result.Type == constants.TypeSRV && result.Category == constants.CategoryProperty && result.Value == "10 50 5060 sip.example.com."
	})

	srvHost := requireResult(t, results, "srv host node", func(result schema.ModuleResult) bool {
		hasSRVTag := slices.Contains(result.Tags, constants.TagSRV)
		return result.Type == constants.TypeSubdomain && result.Category == constants.CategoryNode && result.Value == "sip.example.com" && hasSRVTag
	})
	assertFixtureResultSource(t, source, srvHost.Source)
}
