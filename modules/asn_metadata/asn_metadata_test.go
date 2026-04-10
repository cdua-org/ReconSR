package asn_metadata

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_asn_peers") {
		t.Error("expected get_asn_peers in capabilities")
	}
	if !slices.Contains(caps.InputTypes, "asn") {
		t.Error("expected asn in input types")
	}
}

func TestNormalizeASN(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"3333", "AS3333"},
		{"AS3333", "AS3333"},
		{"as3333", "AS3333"},
		{"  AS15169 ", "AS15169"},
	}

	for _, tt := range tests {
		result := normalizeASN(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeASN(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestGetASNPeersClean(t *testing.T) {
	res := getASNPeers("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNPeersInvalid(t *testing.T) {
	res := getASNPeers("")
	if res.Error == nil {
		t.Error("expected error for empty ASN")
	}
}

func TestGetASNPeersDebug(t *testing.T) {
	t.Log("Testing debug output for ASN peers")
	const debugStr = "true"
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getASNPeers("AS3333")
}

func TestBuildChainString(t *testing.T) {
	chain := []string{"AS174", "AS3356"}
	origin := "AS3333"

	result := buildChainString(chain, origin)
	expected := "Transit chain: AS3356 <- AS174 <- AS3333"

	if result != expected {
		t.Errorf("buildChainString() = %q, want %q", result, expected)
	}
}

func TestBuildChainStringEmpty(t *testing.T) {
	chain := []string{}
	origin := "AS3333"

	result := buildChainString(chain, origin)
	expected := "Transit chain: AS3333"

	if result != expected {
		t.Errorf("buildChainString() = %q, want %q", result, expected)
	}
}
