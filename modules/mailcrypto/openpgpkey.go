package mailcrypto

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

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

func getOPENPGPKEYData(localParts []string, domain string) schema.ModuleExecution {
	execution := modutil.NewExecution("get_openpgpkey")

	if len(localParts) == 1 {
		dbg.Printf("get_openpgpkey email=%q", localParts[0]+"@"+domain)
	} else {
		dbg.Printf("get_openpgpkey domain=%q localParts=%d", domain, len(localParts))
	}

	var rawData []string
	var lastErr error
	var failedAliases []string

	for _, user := range localParts {
		reqCtx, cancel := context.WithTimeout(context.Background(), resolver.DNSBruteTimeout)
		queryDomain := GenerateMailHashDomain(user, domain, "._openpgpkey.")
		dbg.Printf("get_openpgpkey user=%q query=%q", user, queryDomain)
		records, raw, err := resolver.ResolveRecord(reqCtx, queryDomain, 61, nil)
		cancel()
		if err != nil {
			dbg.Printf("get_openpgpkey user=%q domain=%q error=%v", user, domain, err)
			lastErr = err
			failedAliases = append(failedAliases, user)
			continue
		}

		if len(raw) > 0 {
			rawData = append(rawData, string(raw))
		}

		for _, rec := range records {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     "openpgpkey",
				Category: "property",
				Value:    parseOPENPGPKEY(rec),
				Context:  fmt.Sprintf("OPENPGPKEY (%s@%s)", user, domain),
			})
		}
	}

	if lastErr != nil {
		errStr := fmt.Sprintf("failed aliases: %v, last error: %v", failedAliases, lastErr)
		execution.Error = &errStr
	}

	if len(rawData) > 0 {
		execution.RawData = strings.Join(rawData, "\n")
	}

	dbg.Printf("get_openpgpkey domain=%q results=%d", domain, len(execution.Results))
	return execution
}
