package dns

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

var dsDigestTypes = map[byte]string{
	1: "SHA-1",
	2: "SHA-256",
	3: "GOST R 34.11-94",
	4: "SHA-384",
}

// parseDS decodes RFC 3597 wire format (\# <len> <hex>) for DS records (RFC 4034).
// Wire format: 2 bytes Key Tag + 1 byte Algorithm + 1 byte Digest Type + variable length Digest.
func parseDS(raw string) string {
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

	keyTag := uint16(data[0])<<8 | uint16(data[1])
	alg := data[2]
	digestType := data[3]
	digest := hex.EncodeToString(data[4:])

	return fmt.Sprintf("%d %d %d %s", keyTag, alg, digestType, strings.ToUpper(digest))
}

func getDSData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ds",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 43, nil) // 43 is QTYPE for DS
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseDS(rec)

		parts := strings.Fields(parsed)
		if len(parts) < 4 {
			continue
		}

		keyTag := parts[0]
		algName := parts[1]
		digestName := parts[2]

		if algID, err := strconv.Atoi(parts[1]); err == nil && algID >= 0 && algID <= 255 {
			if name, ok := dnskeyAlgorithms[byte(algID)]; ok {
				algName = name
			}
		}

		if dTypeID, err := strconv.Atoi(parts[2]); err == nil && dTypeID >= 0 && dTypeID <= 255 {
			if name, ok := dsDigestTypes[byte(dTypeID)]; ok {
				digestName = name
			}
		}

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parts[3],
			Context: "DS Record, KeyTag: " + keyTag + ", Alg: " + algName + ", Hash: " + digestName,
		})
	}

	return execution
}
