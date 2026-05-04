package mailcrypto

import (
	"strings"
	"testing"
)

func TestGenerateMailHashDomain(t *testing.T) {
	hashDomain := GenerateMailHashDomain("Admin", "example.com", "._openpgpkey.")

	if !strings.HasSuffix(hashDomain, "._openpgpkey.example.com") {
		t.Errorf("Expected suffix '._openpgpkey.example.com', got %s", hashDomain)
	}

	if strings.ContainsAny(hashDomain, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("Resulting hash should be fully lowercased: %s", hashDomain)
	}

	if len(hashDomain) != 69 {
		t.Errorf("Expected total length 69 for OPENPGPKEY hash, got %d", len(hashDomain))
	}
}
