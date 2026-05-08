package mailcrypto

import (
	"strings"
	"testing"
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
