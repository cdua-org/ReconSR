package whois

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestBuildMetadataResults_WhoisServerUsesSemanticType(t *testing.T) {
	m := &module{}
	targetDomain := "example.com"
	whoisServer := "whois.example.com"
	anchor := &schema.EntityRef{Type: constants.TypeWhoisRegistrar, Value: "Registrar of " + targetDomain}

	results := m.buildMetadataResults(&Metadata{WhoisServer: whoisServer}, targetDomain, "WHOIS", anchor)
	if len(results) != 1 {
		t.Fatalf("buildMetadataResults() returned %d results, want 1", len(results))
	}

	got := results[0]
	if got.Type != constants.TypeWhoisServer {
		t.Fatalf("Type = %q, want %q", got.Type, constants.TypeWhoisServer)
	}
	if got.Category != constants.CategoryNode {
		t.Fatalf("Category = %q, want %q", got.Category, constants.CategoryNode)
	}
	if got.Value != whoisServer {
		t.Fatalf("Value = %q, want %q", got.Value, whoisServer)
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
}
