package asn_metadata

import (
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetASNPeers) {
		t.Error("expected get_asn_peers in capabilities")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetASNPrefixes) {
		t.Error("expected get_asn_prefixes in capabilities")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetASNInfo) {
		t.Error("expected get_asn_info in capabilities")
	}
	if !slices.Contains(caps.Functions, constants.FuncGetASNAbuseContacts) {
		t.Error("expected get_asn_abuse_contacts in capabilities")
	}
	if !slices.Contains(caps.InputTypes, constants.TypeASN) {
		t.Error("expected asn in input types")
	}
}

func TestGetASNPeersClean(t *testing.T) {
	res := getASNPeers("AS64512")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNPrefixesClean(t *testing.T) {
	res := getASNPrefixes("AS64513")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNInfoClean(t *testing.T) {
	res := getASNInfo("AS64514")
	if res.Error == nil {
		t.Log("network error may occur, skipping test")
	}
}

func TestGetASNAbuseContactsClean(t *testing.T) {
	res := getASNAbuseContacts("AS64515")
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
	resolver.Options["Debug"] = "true"
	defer func() { resolver.Options["Debug"] = "false" }()

	getASNPeers("AS64516")
	getASNPrefixes("AS64516")
	getASNInfo("AS64516")
	getASNAbuseContacts("AS64516")
}

func TestBuildChainString(t *testing.T) {
	const (
		leftASN   = "AS64518"
		rightASN  = "AS64519"
		originASN = "AS64517"
	)

	result := buildChainString([]string{leftASN, rightASN}, originASN)
	if result != rightASN+chainSeparator+leftASN+chainSeparator+originASN {
		t.Errorf("buildChainString() = %q, want %q", result, rightASN+chainSeparator+leftASN+chainSeparator+originASN)
	}
}

func TestBuildChainStringEmpty(t *testing.T) {
	result := buildChainString([]string{}, "AS64520")
	if result != "AS64520" {
		t.Errorf("buildChainString() = %q, want %q", result, "AS64520")
	}
}

func TestModuleName(t *testing.T) {
	mod := New()
	if mod.Name() != moduleName {
		t.Errorf("expected module name %q, got %q", moduleName, mod.Name())
	}
}

func TestModuleExec(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  constants.TypeASN,
			Value: "AS64521",
		},
		Functions: []string{constants.FuncGetASNPeers, constants.FuncGetASNPrefixes, constants.FuncGetASNInfo, constants.FuncGetASNAbuseContacts, "invalid_func"},
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
		if exec.Function == constants.FuncGetASNPeers {
			foundPeers = true
		}
		if exec.Function == constants.FuncGetASNPrefixes {
			foundPrefixes = true
		}
		if exec.Function == constants.FuncGetASNInfo {
			foundInfo = true
		}
		if exec.Function == constants.FuncGetASNAbuseContacts {
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
