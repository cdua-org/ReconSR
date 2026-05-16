package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestGetSVCBDataEmpty(t *testing.T) {
	execution := getSVCBData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("svcb lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d SVCB/HTTPS results for example.com", len(execution.Results))
}

func TestGetSVCBDataNX(t *testing.T) {
	execution := getSVCBData(context.Background(), "nonexistent.domain.invalid")
	t.Logf("Found %d results for nonexistent domain", len(execution.Results))
}

func TestSVCBCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSVCB) {
		t.Error("expected get_svcb in capabilities")
	}
}
