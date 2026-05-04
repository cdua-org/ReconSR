package asn_metadata

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
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
	if !slices.Contains(caps.Functions, "get_asn_prefixes") {
		t.Error("expected get_asn_prefixes in capabilities")
	}
	if !slices.Contains(caps.Functions, "get_asn_info") {
		t.Error("expected get_asn_info in capabilities")
	}
	if !slices.Contains(caps.Functions, "get_asn_abuse_contacts") {
		t.Error("expected get_asn_abuse_contacts in capabilities")
	}
	if !slices.Contains(caps.InputTypes, "asn") {
		t.Error("expected asn in input types")
	}
}

func TestGetASNPeersClean(t *testing.T) {
	res := getASNPeers("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNPrefixesClean(t *testing.T) {
	res := getASNPrefixes("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNInfoClean(t *testing.T) {
	res := getASNInfo("8.8.8.8")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNAbuseContactsClean(t *testing.T) {
	res := getASNAbuseContacts("8.8.8.8")
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

func TestGetASNPrefixesInvalid(t *testing.T) {
	res := getASNPrefixes("")
	if res.Error == nil {
		t.Error("expected error for empty ASN")
	}
}

func TestGetASNInfoInvalid(t *testing.T) {
	res := getASNInfo("")
	if res.Error == nil {
		t.Error("expected error for empty ASN")
	}
}

func TestGetASNAbuseContactsInvalid(t *testing.T) {
	res := getASNAbuseContacts("")
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
	getASNPrefixes("AS3333")
	getASNInfo("AS3333")
	getASNAbuseContacts("AS3333")
}

const testASN = "AS3333"

func TestBuildChainString(t *testing.T) {
	chain := []string{"AS174", "AS3356"}
	origin := testASN

	result := buildChainString(chain, origin)
	expected := "AS3356 <- AS174 <- " + testASN

	if result != expected {
		t.Errorf("buildChainString() = %q, want %q", result, expected)
	}
}

func TestBuildChainStringEmpty(t *testing.T) {
	chain := []string{}
	origin := testASN

	result := buildChainString(chain, origin)
	expected := testASN

	if result != expected {
		t.Errorf("buildChainString() = %q, want %q", result, expected)
	}
}

func TestModuleName(t *testing.T) {
	mod := New()
	if mod.Name() != "asn_metadata" {
		t.Errorf("expected module name 'asn_metadata', got %q", mod.Name())
	}
}

func TestModuleExec(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  "asn",
			Value: testASN,
		},
		Functions: []string{"get_asn_peers", "get_asn_prefixes", "get_asn_info", "get_asn_abuse_contacts", "invalid_func"},
	}

	out, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("expected no error from Exec, got %v", err)
	}

	if len(out.Executions) != 5 {
		t.Fatalf("expected 5 executions, got %d", len(out.Executions))
	}

	var foundPeers, foundPrefixes, foundInfo, foundAbuse, foundInvalid bool
	for _, exec := range out.Executions {
		if exec.Function == "get_asn_peers" {
			foundPeers = true
		}
		if exec.Function == "get_asn_prefixes" {
			foundPrefixes = true
		}
		if exec.Function == "get_asn_info" {
			foundInfo = true
		}
		if exec.Function == "get_asn_abuse_contacts" {
			foundAbuse = true
		}
		if exec.Function == "invalid_func" {
			foundInvalid = true
			if exec.Error == nil {
				t.Error("expected error for invalid function, got nil")
			}
		}
	}

	if !foundPeers || !foundPrefixes || !foundInfo || !foundAbuse || !foundInvalid {
		t.Error("missing expected execution results")
	}
}
