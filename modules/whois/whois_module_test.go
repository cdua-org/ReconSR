package whois

import (
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestBuildMetadataResults_WhoisServerUsesSemanticType(t *testing.T) {
	m := &module{}
	anchor := &schema.EntityRef{Type: "whois_registrar", Value: "Registrar of example.com"}

	results := m.buildMetadataResults(&Metadata{WhoisServer: "whois.example.com"}, "example.com", "WHOIS", anchor)
	if len(results) != 1 {
		t.Fatalf("buildMetadataResults() returned %d results, want 1", len(results))
	}

	got := results[0]
	if got.Type != "whois_server" {
		t.Fatalf("Type = %q, want %q", got.Type, "whois_server")
	}
	if got.Category != "node" {
		t.Fatalf("Category = %q, want %q", got.Category, "node")
	}
	if got.Value != "whois.example.com" {
		t.Fatalf("Value = %q, want %q", got.Value, "whois.example.com")
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
