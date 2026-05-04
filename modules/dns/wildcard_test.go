package dns

import (
	"context"
	"slices"
	"testing"
)

func TestCheckWildcard(t *testing.T) {
	res := checkWildcard(context.Background(), "example.com")

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

	if !slices.Contains(caps.Functions, "check_wildcard") {
		t.Error("expected check_wildcard in capabilities")
	}
}
