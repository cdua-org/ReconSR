package whois

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestBuildMetadataResults_WhoisServerUsesDomainTag(t *testing.T) {
	targetDomain := "target.client.example.net"
	m, ok := New().(*module)
	if !ok {
		t.Fatalf("New() did not return *module")
	}
	whoisServer := "WHOIS.BACKEND.EXAMPLE.COM"
	anchor := &schema.EntityRef{Type: constants.TypeWhoisRegistrar, Value: "Registrar of " + targetDomain}

	gen := modutil.NewLocalIDGenerator()
	results := m.buildMetadataResults(&Metadata{WhoisServer: whoisServer}, targetDomain, "WHOIS", anchor, gen)
	if len(results) != 1 {
		t.Fatalf("buildMetadataResults() returned %d results, want 1", len(results))
	}

	got := results[0]
	if got.Type != constants.TypeSubdomain {
		t.Fatalf("Type = %q, want %q", got.Type, constants.TypeSubdomain)
	}
	if got.Category != constants.CategoryNode {
		t.Fatalf("Category = %q, want %q", got.Category, constants.CategoryNode)
	}
	if got.Value != "whois.backend.example.com" {
		t.Fatalf("Value = %q, want %q", got.Value, "whois.backend.example.com")
	}
	if !slices.Contains(got.Tags, constants.TagWhoisServer) {
		t.Fatalf("Tags = %v, want to contain %q", got.Tags, constants.TagWhoisServer)
	}
	if got.Context != "Whois Server (WHOIS)" {
		t.Fatalf("Context = %q, want %q", got.Context, "Whois Server (WHOIS)")
	}
	if !got.Applied {
		t.Fatal("Applied = false, want true")
	}
	if !got.OutOfScope {
		t.Fatal("OutOfScope = false, want true")
	}
	if got.Source == nil {
		t.Fatal("Source = nil, want registrar anchor")
	}
	if *got.Source != *anchor {
		t.Fatalf("Source = %+v, want %+v", *got.Source, *anchor)
	}

	expectedLocalID := 1
	if got.LocalID != expectedLocalID {
		t.Fatalf("LocalID = %d, want %d", got.LocalID, expectedLocalID)
	}
}

func TestBuildResults_LocalIDChaining(t *testing.T) {
	m := &module{}
	targetDomain := "example.com"
	metadata := &Metadata{
		Registrant: Contact{
			Name:         []string{"Alice Bob"},
			Organization: []string{"Bob Corp"},
		},
	}

	gen := modutil.NewLocalIDGenerator()
	results := m.buildResults(metadata, targetDomain, "WHOIS", gen)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	anchorID := 1
	if results[0].LocalID != anchorID {
		t.Errorf("anchor LocalID = %d, want %d", results[0].LocalID, anchorID)
	}

	personID := 2
	if results[1].LocalID != personID {
		t.Errorf("person LocalID = %d, want %d", results[1].LocalID, personID)
	}

	orgID := 3
	if results[2].LocalID != orgID {
		t.Errorf("org LocalID = %d, want %d", results[2].LocalID, orgID)
	}
}

func TestAppendHelpers(t *testing.T) {
	m, ok := New().(*module)
	if !ok {
		t.Fatalf("New() did not return *module")
	}
	gen := modutil.NewLocalIDGenerator()
	var results []schema.ModuleResult

	m.appendSlice(&results, []string{"val1", "val2"}, constants.TypeStatus, "ctx", false, nil, "", gen)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	m.appendSlice(&results, []string{"", "  ", "valid@example.net", "invalid-email"}, constants.TypeEmail, "ctx", false, nil, "", gen)
	m.appendSlice(&results, []string{"Bob"}, constants.TypePerson, "ctx", false, nil, "", gen)
	m.appendSlice(&results, []string{"Org"}, constants.TypeOrganization, "ctx", false, nil, "", gen)

	m.appendAddress(&results, []string{"", "  ", "123", "456"}, "address", "Registrant", false, nil, "ctx", gen)
	m.appendAddress(&results, []string{"", "  "}, "address", "Registrant", false, nil, "ctx", gen)

	contact := Contact{
		Name:         []string{"Bob"},
		Organization: []string{"PrivacyProtect"},
		Email:        []string{"bob@example.com"},
		Phone:        []string{"555-1234", "+", "+1-555-123-4567"},
		Fax:          []string{"555-4321"},
		Address:      []string{"123 Street"},
	}
	m.appendContact(&results, &contact, "Registrant", "contactRole", false, nil, "ctx", "target", gen)

	contactEmpty := Contact{}
	m.appendContact(&results, &contactEmpty, "Registrant", "", false, nil, "ctx", "target", gen)

	meta := &Metadata{
		RegistrarURL:   "http://reg.example.com",
		WhoisServer:    "whois.reg.example.com",
		IANAID:         "123",
		DNSSEC:         "unsigned",
		CreationDate:   "2020-01-01",
		UpdatedDate:    "2021-01-01",
		ExpirationDate: "2022-01-01",
		DomainStatus:   []string{"clientUpdateProhibited"},
		NameServers:    []string{"ns1.fallback.example.net", "ns1", "ns3.invalid_domain!!!"},
		Registrar: Contact{
			Name: []string{"Reg"},
		},
	}
	anchor, anchorRes := m.getRegistrarAnchor(meta, "target", "ctx", gen)
	metaRes := m.buildMetadataResults(meta, "target", "ctx", anchor, gen)

	finalResults := make([]schema.ModuleResult, 0, len(results)+len(anchorRes)+len(metaRes))
	finalResults = append(finalResults, results...)
	finalResults = append(finalResults, anchorRes...)
	finalResults = append(finalResults, metaRes...)
	_ = finalResults
}

func TestBuildWhoisServerResult(t *testing.T) {
	res, ok := buildWhoisServerResult("whois.example.com", "example.com")
	if !ok || res.Value != "whois.example.com" {
		t.Errorf("unexpected result: %+v", res)
	}

	_, ok = buildWhoisServerResult("invalid_domain", "ctx")
	if ok {
		t.Errorf("expected failure for invalid domain, got ok")
	}
}
