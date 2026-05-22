package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetHINFODataEmpty(t *testing.T) {
	execution := getHINFOData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("hinfo lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Unexpectedly found HINFO record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetHINFODataNX(t *testing.T) {
	execution := getHINFOData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("hinfo lookup failed: %v", *execution.Error)
	}
}

func TestHINFOCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetHINFO) {
		t.Error("expected get_hinfo in capabilities")
	}
}

func TestBuildHINFOResults(t *testing.T) {
	parsed := &dnsutils.HINFORecord{
		CPU:       "INTEL",
		OS:        "UNIX",
		Formatted: "\"INTEL\" \"UNIX\"",
	}
	source := &schema.EntityRef{Type: constants.TypeHINFO, Value: parsed.Formatted}

	results := buildHINFOResults(parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Source == nil {
			t.Fatalf("expected source to be set for %s", res.Value)
		}
		if res.Source.Type != constants.TypeHINFO || res.Source.Value != parsed.Formatted {
			t.Errorf("expected source to be %s: %s, got %s: %s", constants.TypeHINFO, parsed.Formatted, res.Source.Type, res.Source.Value)
		}
	}
}
