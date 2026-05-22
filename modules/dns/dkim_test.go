package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestGetDKIMDataEmpty(t *testing.T) {
	execution := getDKIMData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("dkim lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetDKIMData(t *testing.T) {
	res := getDKIMData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else {
		t.Logf("DKIM records found (or none): %d", len(res.Results))
	}
}

func TestDKIMCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDKIM) {
		t.Error("expected get_dkim in capabilities")
	}
}
