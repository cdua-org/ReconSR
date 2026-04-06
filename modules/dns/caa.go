package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

var caaRegex = regexp.MustCompile(`(?i)^\d+\s+(issue|issuewild|iodef|issuemail)\s+"(.*)"$`)

func getCAAData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_caa",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// CAA is QTYPE 257. Standard net.Resolver does not support CAA lookups easily,
	// so we pass nil for plainFallback to rely exclusively on DoH servers for CAA.
	records, raw, err := resolver.ResolveRecord(ctx, target, 257, nil)
	if err != nil {
		errMsg := "caa lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		results := parseCAARecord(rec)
		execution.Results = append(execution.Results, results...)
	}

	return execution
}

func parseCAARecord(data string) []schema.ModuleResult {
	// Handle RFC 3597 hex-encoded format (e.g., "\# 21 00 05 69 73...")
	if strings.HasPrefix(data, "\\#") {
		if decoded, err := decodeHexCAA(data); err == nil {
			data = decoded
		}
	}

	var results []schema.ModuleResult

	results = append(results, schema.ModuleResult{
		Type:    "string",
		Value:   data,
		Context: "CAA Record",
	})

	matches := caaRegex.FindStringSubmatch(data)
	if len(matches) < 3 {
		return results
	}

	tag := strings.ToLower(strings.TrimSpace(matches[1]))
	val := strings.TrimSpace(matches[2])

	switch tag {
	case "issue", "issuewild", "issuemail":
		// e.g., "letsencrypt.org", "pki.goog", "amazon.com"
		parts := strings.SplitN(val, ";", 2)
		domain := strings.TrimSpace(parts[0])
		if domain != "" {
			// Certificate Authorities are external infrastructure - mark as OutOfScope
			results = append(results, schema.ModuleResult{
				Type:       "domain",
				Value:      domain,
				Context:    "Authorized CA (" + tag + ")",
				OutOfScope: true,
			})
		}
	case "iodef":
		// e.g., "mailto:security@example.com" or "http://example.com/abuse"
		if strings.HasPrefix(strings.ToLower(val), "mailto:") {
			email := strings.TrimPrefix(val[7:], "//")
			if email != "" {
				results = append(results, schema.ModuleResult{
					Type:       "email",
					Value:      email,
					Context:    "CAA Violation Report",
					OutOfScope: true, // Email contact for abuse reporting is external infra
				})
			}
		} else if strings.HasPrefix(strings.ToLower(val), "http") {
			results = append(results, schema.ModuleResult{
				Type:    "url",
				Value:   val,
				Context: "CAA Violation Report",
			})
		}
	}

	return results
}

// decodeHexCAA converts RFC 3597 hex-encoded CAA data into standard presentation format.
// Format: \# <length> <hex_data>
// CAA RDATA: <flags:1> <tag_len:1> <tag:N> <value:M>
func decodeHexCAA(raw string) (string, error) {
	parts := strings.Fields(raw)
	if len(parts) < 3 || parts[0] != "\\#" {
		return "", errors.New("invalid hex format")
	}

	hexData := strings.Join(parts[2:], "")
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}

	if len(data) < 2 {
		return "", errors.New("data too short")
	}

	flags := data[0]
	tagLen := int(data[1])
	if len(data) < 2+tagLen {
		return "", errors.New("tag length mismatch")
	}

	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])

	return strconv.Itoa(int(flags)) + " " + tag + " \"" + value + "\"", nil
}
