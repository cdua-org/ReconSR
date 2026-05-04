package dns

import (
	"context"
	"slices"
	"testing"
)

func TestGetCNAMEDataEmpty(t *testing.T) {
	execution := getCNAMEData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("cname lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d: %+v", len(execution.Results), execution.Results)
	}
}

func TestGetCNAMEData(t *testing.T) {
	res := getCNAMEData(context.Background(), "example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	}
}

func TestBuildCNAMEResultInScopeSubdomain(t *testing.T) {
	result, ok := buildCNAMEResult("cdn.example.com.", "example.com", "CNAME Record")
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != "subdomain" {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if result.Value != "cdn.example.com" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if result.OutOfScope {
		t.Fatal("expected in-scope CNAME to stay in scope")
	}
}

func TestBuildCNAMEResultOutOfScope(t *testing.T) {
	result, ok := buildCNAMEResult("foo.vendor.example.net.", "example.com", "CNAME Record")
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != "cname_target" {
		t.Fatalf("expected cname_target type, got %q", result.Type)
	}
	if result.Value != "foo.vendor.example.net" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !result.OutOfScope {
		t.Fatal("expected external CNAME to be out of scope")
	}
}

func TestBuildCNAMEResultInvalid(t *testing.T) {
	_, ok := buildCNAMEResult("bad target", "example.com", "CNAME Record")
	if ok {
		t.Fatal("expected invalid CNAME target to be skipped")
	}
}

func TestCNAMECapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_cname") {
		t.Error("expected get_cname in capabilities")
	}
}
