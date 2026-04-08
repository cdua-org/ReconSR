package mailcrypto

import (
	"strings"
	"testing"
)

func TestGenerateMailHashDomain(t *testing.T) {
	// RFC 8162 specifies:
	// Local-part "hugh" lowercase -> SHA256 -> base32 -> truncate -> smimecert
	// SHA256("hugh"): 8cb...
	// For simplicity, we just test if it encodes the hash natively and lowers the case.

	hashDomain := GenerateMailHashDomain("Admin", "example.com", "._openpgpkey.")

	if !strings.HasSuffix(hashDomain, "._openpgpkey.example.com") {
		t.Errorf("Expected suffix '._openpgpkey.example.com', got %s", hashDomain)
	}

	if strings.ContainsAny(hashDomain, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("Resulting hash should be fully lowercased: %s", hashDomain)
	}

	// base32 encoded SHA256 truncated to 28 bytes is exactly 45 characters long.
	// 45 + len("._openpgpkey.example.com") = 45 + 24 = 69 characters.
	if len(hashDomain) != 69 {
		t.Errorf("Expected total length 69 for OPENPGPKEY hash, got %d", len(hashDomain))
	}
}
