package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestGetNSECData(t *testing.T) {
	execution := getNSECData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

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
	execution := getNSECData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

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
	rootResult := extractNSECDomain("*.example.org.", "example.org", "missing.example.net", "NSEC Next Domain", modutil.NewLocalIDGenerator())
	if rootResult == nil {
		t.Fatal("expected wildcard root domain result")
	}
	if rootResult.Type != constants.TypeDomain {
		t.Fatalf("expected normalized root domain type, got %q", rootResult.Type)
	}
	if rootResult.Value != "example.org" {
		t.Fatalf("expected normalized root wildcard value, got %q", rootResult.Value)
	}
	if !slices.Contains(rootResult.Tags, constants.TagNSEC) {
		t.Fatalf("expected nsec tag on root result, got %+v", rootResult.Tags)
	}

	result := extractNSECDomain("*.wild.example.net.", "example.net", "missing.example.edu", "NSEC Next Domain", modutil.NewLocalIDGenerator())
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
	if !slices.Contains(result.Tags, constants.TagNSEC) {
		t.Fatalf("expected nsec tag, got %+v", result.Tags)
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

func TestParseNSECRecordSource(t *testing.T) {
	rec := resolver.DoHDnsRecord{
		Name: "current.example.com.",
		Data: "next.example.com. A AAAA RRSIG NSEC",
	}

	results := parseNSECRecord(rec, "example.com", "nx.example.com", "NSEC Context", modutil.NewLocalIDGenerator())

	if len(results) < 3 {
		t.Fatalf("expected at least 3 results, got %d", len(results))
	}

	// 1. Current Subdomain
	currentSub := results[0]
	if currentSub.Type != constants.TypeSubdomain || currentSub.Value != "current.example.com" {
		t.Fatalf("expected current subdomain, got %s %s", currentSub.Type, currentSub.Value)
	}

	// 2. NSEC Property
	primary := results[1]
	if primary.Type != constants.TypeNSEC {
		t.Fatalf("expected primary result to be NSEC, got %s", primary.Type)
	}

	if primary.Value != "current.example.com NSEC next.example.com A AAAA RRSIG NSEC" {
		t.Errorf("expected normalized value without trailing dots, got %q", primary.Value)
	}

	if primary.Source == nil || primary.Source.Value != "current.example.com" {
		t.Errorf("expected NSEC property to have Source = current.example.com, got %v", primary.Source)
	}

	// 3. Leaked Subdomain
	leakedSub := results[2]
	expectedSource := &schema.EntityRef{Type: primary.Type, Value: primary.Value}

	if leakedSub.Source == nil || leakedSub.Source.Type != expectedSource.Type || leakedSub.Source.Value != expectedSource.Value {
		t.Errorf("expected Source %v, got %v", expectedSource, leakedSub.Source)
	}
}

func TestParseNSEC3RecordSource(t *testing.T) {
	rec := resolver.DoHDnsRecord{
		Name: "0p9mhaveqvm6t7v8pon2iu430l8kcmpo.example.com.",
		Data: "1 0 10 AABBCCDD EEFF00112233 A RRSIG",
	}

	results := parseNSEC3Record(rec, "NSEC3 Context", modutil.NewLocalIDGenerator())

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	primary := results[0]
	if primary.Type != constants.TypeNSEC {
		t.Fatalf("expected primary result to be NSEC, got %s", primary.Type)
	}

	if primary.Value != "0p9mhaveqvm6t7v8pon2iu430l8kcmpo.example.com NSEC3 1 0 10 AABBCCDD EEFF00112233 A RRSIG" {
		t.Errorf("expected normalized NSEC3 value without trailing dots, got %q", primary.Value)
	}

	expectedSource := &schema.EntityRef{Type: primary.Type, Value: primary.Value}

	for i := 1; i < len(results); i++ {
		if results[i].Source == nil {
			t.Errorf("expected Source to be set for result %d", i)
		} else if results[i].Source.Type != expectedSource.Type || results[i].Source.Value != expectedSource.Value {
			t.Errorf("expected Source %v, got %v", expectedSource, results[i].Source)
		}
	}
}
