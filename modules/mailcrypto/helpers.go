package mailcrypto

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

// GenerateMailHashDomain computes the specialized email hash per RFC 7929 / 8162
// and builds the query domain using the specified prefix (e.g., "._openpgpkey.").
func GenerateMailHashDomain(localPart, domain, prefix string) string {
	hash := sha256.Sum256([]byte(strings.ToLower(localPart)))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:28])
	return fmt.Sprintf("%s%s%s", strings.ToLower(encoded), prefix, domain)
}
