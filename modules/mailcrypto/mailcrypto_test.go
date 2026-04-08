package mailcrypto

import (
	"slices"
	"testing"
)

func TestMailCryptoCapabilities(t *testing.T) {
	m := &module{}
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
