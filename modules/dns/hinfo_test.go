package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestGetHINFODataEmpty(t *testing.T) {
	// example.com very rarely has a HINFO record
	execution := getHINFOData("example.com")

	if execution.Error != nil {
		t.Logf("hinfo lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Unexpectedly found HINFO record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetHINFODataNX(t *testing.T) {
	execution := getHINFOData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") { // Status 3 is NXDOMAIN
		t.Logf("hinfo lookup failed: %v", *execution.Error)
	}
}

func TestHINFOCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_hinfo") {
		t.Error("expected get_hinfo in capabilities")
	}
}
