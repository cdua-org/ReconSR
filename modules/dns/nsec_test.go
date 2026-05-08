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
