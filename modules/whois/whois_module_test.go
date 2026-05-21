package whois

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestBuildMetadataResults_WhoisServerUsesDomainTag(t *testing.T) {
	m := &module{}
	targetDomain := "example.net"
	whoisServer := "WHOIS.EXAMPLE.COM"
	anchor := &schema.EntityRef{Type: constants.TypeWhoisRegistrar, Value: "Registrar of " + targetDomain}

	results := m.buildMetadataResults(&Metadata{WhoisServer: whoisServer}, targetDomain, "WHOIS", anchor)
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
	if got.Value != "whois.example.com" {
		t.Fatalf("Value = %q, want %q", got.Value, "whois.example.com")
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

	expectedLocalID := modutil.BuildLocalID(anchor, got.Type, got.Value)
	if got.LocalID != expectedLocalID {
		t.Fatalf("LocalID = %q, want %q", got.LocalID, expectedLocalID)
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

	results := m.buildResults(metadata, targetDomain, "WHOIS")

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	anchorID := modutil.BuildLocalID(nil, constants.TypeWhoisRegistrant, "Registrant of "+targetDomain)
	if results[0].LocalID != anchorID {
		t.Errorf("anchor LocalID = %q, want %q", results[0].LocalID, anchorID)
	}

	personID := modutil.BuildLocalID(&schema.EntityRef{LocalID: anchorID}, constants.TypePerson, "Alice Bob")
	if results[1].LocalID != personID {
		t.Errorf("person LocalID = %q, want %q", results[1].LocalID, personID)
	}

	orgID := modutil.BuildLocalID(&schema.EntityRef{LocalID: anchorID}, constants.TypeOrganization, "Bob Corp")
	if results[2].LocalID != orgID {
		t.Errorf("org LocalID = %q, want %q", results[2].LocalID, orgID)
	}
}
