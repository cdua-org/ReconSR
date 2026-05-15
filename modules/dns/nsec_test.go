package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetNSECData(t *testing.T) {
	execution := getNSECData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("nsec lookup failed (this can vary by network): %v", *execution.Error)
		return
	}

	foundNsec := false
	for _, res := range execution.Results {
		if strings.Contains(res.Context, "NSEC") {
			foundNsec = true
			break
		}
	}

	if !foundNsec {
		t.Logf("Expected some NSEC/NSEC3 records for example.com, got none. This can happen on some networks.")
	}
}

func TestGetNSECDataEmpty(t *testing.T) {
	execution := getNSECData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("nsec lookup failed: %v", *execution.Error)
	}

	t.Logf("Found %d NSEC results for nonexistent domain", len(execution.Results))
	for _, res := range execution.Results {
		if res.Type == "" {
			t.Errorf("expected well-formed ModuleResult, got empty Type")
		}
	}
}

func TestExtractNSECDomainWildcard(t *testing.T) {
	rootResult := extractNSECDomain("*.example.org.", "example.org", "missing.example.net", "NSEC Next Domain")
	if rootResult == nil {
		t.Fatal("expected wildcard root domain result")
	}
	if rootResult.Type != constants.TypeDomain {
		t.Fatalf("expected normalized root domain type, got %q", rootResult.Type)
	}
	if rootResult.Value != "example.org" {
		t.Fatalf("expected normalized root wildcard value, got %q", rootResult.Value)
	}

	result := extractNSECDomain("*.wild.example.net.", "example.net", "missing.example.edu", "NSEC Next Domain")
	if result == nil {
		t.Fatal("expected wildcard NSEC domain result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected normalized subdomain type, got %q", result.Type)
	}
	if result.Value != "wild.example.net" {
		t.Fatalf("expected normalized wildcard value, got %q", result.Value)
	}
	if !slices.Contains(result.Tags, constants.TagWildcard) {
		t.Fatalf("expected wildcard tag, got %+v", result.Tags)
	}
	if result.Context != "*.wild.example.net" {
		t.Fatalf("expected full wildcard context, got %q", result.Context)
	}
}

func TestNSECCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetNSEC) {
		t.Error("expected get_nsec in capabilities")
	}
}
