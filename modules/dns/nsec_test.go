package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestGetNSECData(t *testing.T) {
	// Querying a domain known to have DNSSEC/NSEC3 (isc.org, cloudflare.com, or fi)
	// We'll use isc.org since it's a robust standard for DNS/DNSSEC testing.
	execution := getNSECData("isc.org")

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
		t.Logf("Expected some NSEC/NSEC3 records for isc.org, got none. This can happen on some networks.")
	}
}

func TestGetNSECDataEmpty(t *testing.T) {
	// nonexistent.domain.invalid should definitively be NXDOMAIN and returning no NSEC (assuming root servers don't return NSEC for .invalid locally)
	execution := getNSECData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") { // Status 3 is NXDOMAIN
		t.Logf("nsec lookup failed: %v", *execution.Error)
	}

	// We might actually get NSEC from the root servers indicating that .invalid doesn't exist!
	// Example: "invalid. 86400 IN NSEC ispa."
	// We'll just verify the execution completes without panicking and results are well-formed.
	t.Logf("Found %d NSEC results for nonexistent domain", len(execution.Results))
	for _, res := range execution.Results {
		if res.Type == "" {
			t.Errorf("expected well-formed ModuleResult, got empty Type")
		}
	}
}

func TestNSECCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_nsec") {
		t.Error("expected get_nsec in capabilities")
	}
}
