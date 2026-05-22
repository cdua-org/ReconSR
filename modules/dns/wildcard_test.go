package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestCheckWildcard(t *testing.T) {
	res := checkWildcard(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else if len(res.Results) > 0 {
		t.Logf("Unexpected wildcard records found for example.com: %+v", res.Results)
	}
}

func TestWildcardCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncCheckWildcard) {
		t.Error("expected check_wildcard in capabilities")
	}
}
