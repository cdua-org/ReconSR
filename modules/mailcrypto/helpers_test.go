package mailcrypto

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestGenerateMailHashDomain(t *testing.T) {
	hashDomain := GenerateMailHashDomain("Admin", "example.org", hashPrefixOpenPGPKey)

	expectedSuffix := hashPrefixOpenPGPKey + "example.org"
	if !strings.HasSuffix(hashDomain, expectedSuffix) {
		t.Errorf("Expected suffix %q, got %s", expectedSuffix, hashDomain)
	}

	if strings.ContainsAny(hashDomain, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("Resulting hash should be fully lowercased: %s", hashDomain)
	}

	if len(hashDomain) != 69 {
		t.Errorf("Expected total length 69 for OPENPGPKEY hash, got %d", len(hashDomain))
	}
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}
