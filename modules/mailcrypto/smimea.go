package mailcrypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var smimeaUsages = map[byte]string{
	0: "PKIX-CA",
	1: "PKIX-EE",
	2: "DANE-TA",
	3: "DANE-EE",
}

var smimeaSelectors = map[byte]string{
	0: "Cert",
	1: "SPKI",
}

var smimeaMatchingTypes = map[byte]string{
	0: "Full",
	1: "SHA256",
	2: "SHA512",
}

// parseSMIMEA decodes RFC 3597 wire format (\# <len> <hex>) for SMIMEA records (RFC 8162).
func parseSMIMEA(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 4 {
		return raw
	}

	usage := data[0]
	selector := data[1]
	matchingType := data[2]
	assocData := hex.EncodeToString(data[3:])

	return fmt.Sprintf("%d %d %d %s", usage, selector, matchingType, assocData)
}

func mapSMIMEAContext(usageStr, selectorStr, matchingTypeStr string) string {
	usage := usageStr
	if uNum, err := strconv.Atoi(usageStr); err == nil && uNum >= 0 && uNum <= 255 {
		if name, ok := smimeaUsages[byte(uNum)]; ok {
			usage = name
		}
	}

	selector := selectorStr
	if sNum, err := strconv.Atoi(selectorStr); err == nil && sNum >= 0 && sNum <= 255 {
		if name, ok := smimeaSelectors[byte(sNum)]; ok {
			selector = name
		}
	}

	matching := matchingTypeStr
	if mNum, err := strconv.Atoi(matchingTypeStr); err == nil && mNum >= 0 && mNum <= 255 {
		if name, ok := smimeaMatchingTypes[byte(mNum)]; ok {
			matching = name
		}
	}

	return fmt.Sprintf("SMIMEA: %s, %s, %s", usage, selector, matching)
}

func getSMIMEAData(localParts []string, domain string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_smimea",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var rawData []string
	var lastErr error

	for _, user := range localParts {
		queryDomain := GenerateMailHashDomain(user, domain, "._smimecert.")
		records, raw, err := resolver.ResolveRecord(ctx, queryDomain, 53, nil) // 53 is QTYPE for SMIMEA
		if err != nil {
			lastErr = err
			continue
		}

		if len(raw) > 0 {
			rawData = append(rawData, string(raw))
		}

		for _, rec := range records {
			parsed := parseSMIMEA(rec)

			parts := strings.Fields(parsed)
			if len(parts) >= 4 {
				ctxParams := mapSMIMEAContext(parts[0], parts[1], parts[2])
				ctxStr := fmt.Sprintf("SMIMEA (%s@%s) - %s", user, domain, ctxParams)

				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   parts[3],
					Context: ctxStr,
				})
			} else {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   parsed,
					Context: fmt.Sprintf("SMIMEA (%s@%s)", user, domain),
				})
			}
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
