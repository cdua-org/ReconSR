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

var dnskeyAlgorithms = map[byte]string{
	1:   "RSAMD5",
	2:   "DH",
	3:   "DSA",
	5:   "RSASHA1",
	6:   "DSA-NSEC3-SHA1",
	7:   "RSASHA1-NSEC3-SHA1",
	8:   "RSASHA256",
	10:  "RSASHA512",
	12:  "ECC-GOST",
	13:  "ECDSAP256SHA256",
	14:  "ECDSAP384SHA384",
	15:  "ED25519",
	16:  "ED448",
	252: "INDIRECT",
	253: "PRIVATEDNS",
	254: "PRIVATEOID",
}

// parseDNSKEY decodes RFC 3597 wire format (\# <len> <hex>) for DNSKEY records (RFC 4034).
// Wire format: 2 bytes Flags + 1 byte Protocol + 1 byte Algorithm + variable length Public Key.
func parseDNSKEY(raw string) string {
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

	flags := uint16(data[0])<<8 | uint16(data[1])
	protocol := data[2]
	alg := data[3]
	pubKey := base64.StdEncoding.EncodeToString(data[4:])

	algName, ok := dnskeyAlgorithms[alg]
	if !ok {
		algName = strconv.Itoa(int(alg))
	}

	return fmt.Sprintf("%d %d %s %s", flags, protocol, algName, pubKey)
}

func getDNSKEYData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_dnskey",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 48, nil) // 48 is QTYPE for DNSKEY
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseDNSKEY(rec)

		parts := strings.Fields(parsed)
		if len(parts) >= 4 {
			flagsStr := parts[0]
			algStr := parts[2]

			algName := algStr
			if algNum, err := strconv.Atoi(algStr); err == nil && algNum >= 0 && algNum <= 255 {
				if mappedName, ok := dnskeyAlgorithms[byte(algNum)]; ok {
					algName = mappedName
				}
			}

			switch flagsStr {
			case "257":
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   parts[3],
					Context: "DNSKEY KSK, Alg: " + algName,
				})
			case "256":
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   parts[3],
					Context: "DNSKEY ZSK, Alg: " + algName,
				})
			}
		}
	}

	return execution
}
