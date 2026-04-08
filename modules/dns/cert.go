package dns

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var certTypes = map[uint16]string{
	1:   "PKIX (X.509)",
	2:   "SPKI",
	3:   "PGP",
	4:   "IPKIX (URL X.509)",
	5:   "ISPKI (URL SPKI)",
	6:   "IPGP (Fingerprint PGP)",
	7:   "ACPKIX",
	8:   "IACPKIX",
	253: "URI Private",
	254: "OID Private",
}

// parseCERT decodes RFC 3597 wire format (\# <len> <hex>) for CERT records (RFC 4398).
// Wire format: 2 bytes Type + 2 bytes Key Tag + 1 byte Algorithm + variable length Certificate payload.
func parseCERT(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 5 {
		return raw
	}

	cType := uint16(data[0])<<8 | uint16(data[1])
	keyTag := uint16(data[2])<<8 | uint16(data[3])
	alg := data[4]
	certBase64 := base64.StdEncoding.EncodeToString(data[5:])

	return fmt.Sprintf("%d %d %d %s", cType, keyTag, alg, certBase64)
}

func getCERTData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_cert",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 37, nil) // 37 is QTYPE for CERT
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseCERT(rec)

		parts := strings.Fields(parsed)
		if len(parts) < 4 {
			continue
		}

		cTypeName := parts[0]
		keyTag := parts[1]
		algName := parts[2]

		if tNum, err := strconv.Atoi(parts[0]); err == nil && tNum >= 0 && tNum <= 65535 {
			if name, ok := certTypes[uint16(tNum)]; ok {
				cTypeName = name
			}
		}

		if aNum, err := strconv.Atoi(parts[2]); err == nil && aNum >= 0 && aNum <= 255 {
			if name, ok := dnskeyAlgorithms[byte(aNum)]; ok {
				algName = name
			}
		}

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parts[3],
			Context: "CERT Record, Type: " + cTypeName + ", KeyTag: " + keyTag + ", Alg: " + algName,
		})
	}

	return execution
}
