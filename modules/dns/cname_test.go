package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
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
	result, ok := buildCNAMEResult("cdn.example.com.", "cname-scope.example.com", "CNAME Record")
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if !slices.Contains(result.Tags, constants.TagCNAME) {
		t.Fatalf("missing tag %q", constants.TagCNAME)
	}
	if result.Value != "cdn.example.com" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if result.OutOfScope {
		t.Fatal("expected in-scope CNAME to stay in scope")
	}
}

func TestBuildCNAMEResultOutOfScope(t *testing.T) {
	result, ok := buildCNAMEResult("vendor.foo.example.net.", "cname-oos.example.com", "CNAME Record")
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if !slices.Contains(result.Tags, constants.TagCNAME) {
		t.Fatalf("missing tag %q", constants.TagCNAME)
	}
	if result.Value != "vendor.foo.example.net" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !result.OutOfScope {
		t.Fatal("expected external CNAME to be out of scope")
	}
}

func TestBuildCNAMEResultInvalid(t *testing.T) {
	_, ok := buildCNAMEResult("bad target", "cname-invalid.example.com", "CNAME Record")
	if ok {
		t.Fatal("expected invalid CNAME target to be skipped")
	}
}

func TestBuildCNAMEResultSelfReferential(t *testing.T) {
	_, ok := buildCNAMEResult("example.com.", "example.com", "CNAME Record")
	if ok {
		t.Fatal("expected self-referential CNAME to be skipped")
	}
}

func TestCNAMECapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetCNAME) {
		t.Error("expected get_cname in capabilities")
	}
}
