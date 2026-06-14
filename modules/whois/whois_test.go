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
