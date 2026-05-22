package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetTXTDataEmpty(t *testing.T) {
	execution := getTXTData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("txt lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetTXTData(t *testing.T) {
	res := getTXTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else {
		t.Logf("TXT/SPF records found (or none): %d", len(res.Results))
	}
}

func TestTXTCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetTXT) {
		t.Error("expected get_txt in capabilities")
	}
}

func TestGetTXTData_LocalIDChaining(t *testing.T) {
	exec := getTXTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}
	if len(exec.Results) < 2 {
		t.Skip("Expected multiple results to verify chaining, skipping test")
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}
}

func TestBuildSPFEntityResults(t *testing.T) {
	spf := "v=spf1 ip4:198.51.100.10 ip6:2001:db8::1 include:spf.example.net a:web.example.org mx:relay.example.edu -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "example.com", modutil.NewLocalIDGenerator())

	requireSPFResult(t, results, constants.TypeIPv4, "198.51.100.10", "SPF ip4", false)
	requireSPFResult(t, results, constants.TypeIPv6, "2001:db8::1", "SPF ip6", false)
	requireSPFResult(t, results, constants.TypeSubdomain, "spf.example.net", "SPF include", true)
	requireSPFResult(t, results, constants.TypeSubdomain, "web.example.org", "SPF a", true)
	requireSPFResult(t, results, constants.TypeSubdomain, "relay.example.edu", "SPF mx", true)

	for _, res := range results {
		if !slices.Contains(res.Tags, constants.TagSPF) {
			t.Fatalf("expected tag %q on result %q, got %v", constants.TagSPF, res.Value, res.Tags)
		}
		if res.Source == nil || res.Source.Type != constants.TypeSPF {
			t.Fatalf("expected source linked to SPF record, got %+v", res.Source)
		}
	}
}

func TestBuildSPFEntityResultsSelfReferentialSkipped(t *testing.T) {
	spf := "v=spf1 include:samehost.example.com redirect=samehost.example.com -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "samehost.example.com", modutil.NewLocalIDGenerator())

	for _, res := range results {
		if res.Value == "samehost.example.com" {
			t.Fatal("expected self-referential SPF domain to NOT be emitted")
		}
	}
}

func TestBuildSPFEntityResultsEmptySPF(t *testing.T) {
	spf := "v=spf1 -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "example.com", modutil.NewLocalIDGenerator())
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty SPF, got %d", len(results))
	}
}

func requireSPFResult(t *testing.T, results []schema.ModuleResult, wantType, wantValue, wantContext string, wantOOS bool) {
	t.Helper()

	for _, res := range results {
		if res.Type == wantType && res.Value == wantValue {
			if res.Context != wantContext {
				t.Fatalf("result %q context = %q, want %q", wantValue, res.Context, wantContext)
			}
			if res.OutOfScope != wantOOS {
				t.Fatalf("result %q out_of_scope = %v, want %v", wantValue, res.OutOfScope, wantOOS)
			}
			return
		}
	}

	t.Fatalf("expected SPF result type=%q value=%q not found", wantType, wantValue)
}
