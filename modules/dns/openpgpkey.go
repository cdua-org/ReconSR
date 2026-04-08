package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// parseOPENPGPKEY decodes RFC 3597 wire format (\# <len> <hex>) for OPENPGPKEY records (RFC 7929).
// The RDATA contains the OpenPGP Transferable Public Key.
func parseOPENPGPKEY(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) == 0 {
		return raw
	}

	return base64.StdEncoding.EncodeToString(data)
}

func generateOpenPGPKeyDomain(localPart, domain string) string {
	hash := sha256.Sum256([]byte(strings.ToLower(localPart)))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:28])
	return fmt.Sprintf("%s._openpgpkey.%s", strings.ToLower(encoded), domain)
}

func getOPENPGPKEYData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_openpgpkey",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	users := []string{"admin", "administrator", "postmaster", "hostmaster", "security", "webmaster", "info"}
	var rawData []string
	var lastErr error

	for _, user := range users {
		queryDomain := generateOpenPGPKeyDomain(user, target)
		records, raw, err := resolver.ResolveRecord(ctx, queryDomain, 61, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if len(raw) > 0 {
			rawData = append(rawData, string(raw))
		}
		for _, rec := range records {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "string",
				Value:   parseOPENPGPKEY(rec),
				Context: fmt.Sprintf("OPENPGPKEY (%s@%s)", user, target),
			})
		}
	}

	if len(execution.Results) == 0 && lastErr != nil {
		errStr := lastErr.Error()
		execution.Error = &errStr
	} else if len(rawData) > 0 {
		execution.RawData = strings.Join(rawData, "\n")
	}

	return execution
}
