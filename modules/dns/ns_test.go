package dns

import (
	"slices"
	"testing"
)

func TestGetNSDataEmpty(t *testing.T) {
	execution := getNSData("nonexistent.domain.invalid")

	if execution.Error != nil {
		// Just log error for CI network flakes
		t.Logf("ns lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetNSData(t *testing.T) {
	res := getNSData("example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one NS for example.com")
	case res.Results[0].Type != "domain" && res.Results[0].Type != "string":
		t.Errorf("unexpected type: %s", res.Results[0].Type)
	}
}

func TestNSCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_ns") {
		t.Error("expected get_ns in capabilities")
	}
}
