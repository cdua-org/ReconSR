package mailcrypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
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
	execution := modutil.NewExecution(constants.FuncGetSmimea)
	gen := modutil.NewLocalIDGenerator()

	if len(localParts) == 1 {
		dbg.Printf("%s email=%q", constants.FuncGetSmimea, localParts[0]+"@"+domain)
	} else {
		dbg.Printf("%s domain=%q local_parts=%d", constants.FuncGetSmimea, domain, len(localParts))
	}

	var rawData []string
	var lastErr error
	var failedAliases []string

	for _, user := range localParts {
		reqCtx, cancel := context.WithTimeout(context.Background(), resolver.DNSBruteTimeout)
		queryDomain := GenerateMailHashDomain(user, domain, hashPrefixSMIMEA)
		dbg.Printf("%s user=%q query=%q", constants.FuncGetSmimea, user, queryDomain)
		records, raw, err := resolveRecord(reqCtx, queryDomain, 53, nil)
		cancel()
		if err != nil {
			dbg.Printf("%s error user=%q domain=%q query=%q err=%v", constants.FuncGetSmimea, user, domain, queryDomain, err)
			lastErr = err
			failedAliases = append(failedAliases, user)
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
				ctxStr := fmt.Sprintf("%s (%s@%s) - %s", ctxSMIMEA, user, domain, ctxParams)

				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:     constants.TypeSMIMEA,
					Category: constants.CategoryProperty,
					Value:    parts[3],
					Context:  ctxStr,
					LocalID:  gen.NextID(),
				})
			} else {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:     constants.TypeSMIMEA,
					Category: constants.CategoryProperty,
					Value:    parsed,
					Context:  fmt.Sprintf("%s (%s@%s)", ctxSMIMEA, user, domain),
					LocalID:  gen.NextID(),
				})
			}
		}
	}

	if lastErr != nil {
		errStr := fmt.Sprintf("failed aliases: %v, last error: %v", failedAliases, lastErr)
		execution.Error = &errStr
	}

	if len(rawData) > 0 {
		execution.RawData = strings.Join(rawData, "\n")
	}

	dbg.Printf("%s domain=%q results=%d", constants.FuncGetSmimea, domain, len(execution.Results))
	return execution
}
