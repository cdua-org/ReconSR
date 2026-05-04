package mailcrypto

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestMailCryptoCapabilities(t *testing.T) {
	m := &module{}

	resolver.DisableMailcryptoBruteForce = true
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_openpgpkey") {
		t.Error("expected get_openpgpkey in capabilities")
	}

	if !slices.Contains(caps.Functions, "get_smimea") {
		t.Error("expected get_smimea in capabilities")
	}

	if !slices.Contains(caps.Functions, "preflight_dns") {
		t.Error("expected preflight_dns in capabilities")
	}

	if slices.Contains(caps.InputTypes, "domain") {
		t.Error("unexpected domain in input types")
	}

	if slices.Contains(caps.InputTypes, "subdomain") {
		t.Error("unexpected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, "email") {
		t.Error("expected email in input types")
	}

	resolver.DisableMailcryptoBruteForce = false
	caps, err = m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}
	if !slices.Contains(caps.InputTypes, "domain") {
		t.Error("expected domain in input types")
	}

	if !slices.Contains(caps.InputTypes, "subdomain") {
		t.Error("expected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, "email") {
		t.Error("expected email in input types")
	}
}
