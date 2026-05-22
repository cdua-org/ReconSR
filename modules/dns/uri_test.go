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

func TestGetURIDataEmpty(t *testing.T) {
	execution := getURIData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("uri lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Found URI record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetURIDataNX(t *testing.T) {
	execution := getURIData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("uri lookup failed: %v", *execution.Error)
	}
}

func TestURICapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetURI) {
		t.Error("expected get_uri in capabilities")
	}
}

func TestBuildURIResults(t *testing.T) {
	parsed := &dnsutils.URIRecord{
		Priority:  "10",
		Weight:    "100",
		Target:    "https://example.com",
		Formatted: "10 100 \"https://example.com\"",
	}
	source := &schema.EntityRef{Type: constants.TypeURI, Value: parsed.Formatted}

	results := buildURIResults(parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Type != constants.TypeURL {
		t.Errorf("expected type %s, got %s", constants.TypeURL, res.Type)
	}
	if res.Value != parsed.Target {
		t.Errorf("expected value %s, got %s", parsed.Target, res.Value)
	}
	if res.Source == nil {
		t.Fatal("expected source to be set")
	}
	if res.Source.Type != constants.TypeURI || res.Source.Value != parsed.Formatted {
		t.Errorf("expected source to be %s: %s, got %s: %s", constants.TypeURI, parsed.Formatted, res.Source.Type, res.Source.Value)
	}
}
