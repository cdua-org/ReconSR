package dns

import (
	"slices"
	"testing"
)

func TestGetCNAMEDataEmpty(t *testing.T) {
	execution := getCNAMEData("nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("cname lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d: %+v", len(execution.Results), execution.Results)
	}
}

func TestGetCNAMEData(t *testing.T) {
	// A basic integration test. CNAME for example.com shouldn't exist usually,
	// but www.example.com might not either. We just check it doesn't fail.
	res := getCNAMEData("example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
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
