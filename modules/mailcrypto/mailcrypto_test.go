package mailcrypto

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/schema"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestMailCryptoCapabilities(t *testing.T) {
	m := &module{}

	originalDisableMailcryptoBruteForce := resolver.DisableMailcryptoBruteForce
	t.Cleanup(func() {
		resolver.DisableMailcryptoBruteForce = originalDisableMailcryptoBruteForce
	})

	resolver.DisableMailcryptoBruteForce = true
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetOpenpgpkey) {
		t.Error("expected get_openpgpkey in capabilities")
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSmimea) {
		t.Error("expected get_smimea in capabilities")
	}

	if !slices.Contains(caps.Functions, constants.FuncPreflightDNS) {
		t.Error("expected preflight_dns in capabilities")
	}

	if slices.Contains(caps.InputTypes, constants.TypeDomain) {
		t.Error("unexpected domain in input types")
	}

	if slices.Contains(caps.InputTypes, constants.TypeSubdomain) {
		t.Error("unexpected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeEmail) {
		t.Error("expected email in input types")
	}

	resolver.DisableMailcryptoBruteForce = false
	caps, err = m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}
	if !slices.Contains(caps.InputTypes, constants.TypeDomain) {
		t.Error("expected domain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeSubdomain) {
		t.Error("expected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeEmail) {
		t.Error("expected email in input types")
	}
}

func TestModule_LocalIDChaining_Preflight(t *testing.T) {
	in := schema.Entity{Type: constants.TypeDomain, Value: "example.com"}
	res := handlePreflightDNS(context.Background(), "example.com", in)
	requireUniqueLocalIDs(t, res.Results)
}
