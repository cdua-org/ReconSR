package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestGetDomainKeyDataEmpty(t *testing.T) {
	execution := getDomainKeyData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("domainkey lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetDomainKeyData(t *testing.T) {
	res := getDomainKeyData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else {
		t.Logf("DomainKey records found (or none): %d", len(res.Results))
	}
}

func TestDomainKeyCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDomainKey) {
		t.Error("expected get_domainkey in capabilities")
	}
}
