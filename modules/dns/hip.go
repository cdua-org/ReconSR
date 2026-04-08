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

var hipAlgorithms = map[byte]string{
	1: "DSA",
	2: "RSA",
	3: "ECDSA",
	4: "ECDSA_LOW",
	5: "DSA_LOW",
	6: "RSA_LOW",
	7: "EDDSA",
	8: "EDDSA_LOW",
	9: "PQC",
}

// parseHIP decodes RFC 3597 wire format (\# <len> <hex>) for HIP records (RFC 8005).
// In wire format, rendezvous servers are complex wire-encoded domains. We'll extract main crypto parameters.
func parseHIP(raw string) string {
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

	hitLen := int(data[0])
	alg := data[1]
	pkLen := int(uint16(data[2])<<8 | uint16(data[3]))

	if len(data) < 4+hitLen+pkLen {
		return raw
	}

	hit := hex.EncodeToString(data[4 : 4+hitLen])
	pubKeyBase64 := base64.StdEncoding.EncodeToString(data[4+hitLen : 4+hitLen+pkLen])

	// Optional Rendezvous Servers are trailing, skipped in pure hex fallback.
	return fmt.Sprintf("%d %s %s", alg, strings.ToUpper(hit), pubKeyBase64)
}

func getHIPData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_hip",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 55, nil) // 55 is QTYPE for HIP
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseHIP(rec)

		parts := strings.Fields(parsed)
		if len(parts) < 3 {
			continue
		}

		algName := parts[0]
		hit := parts[1]
		pubKey := parts[2]

		var rendezvousers []string
		if len(parts) > 3 {
			rendezvousers = parts[3:]
		}

		if aNum, err := strconv.Atoi(parts[0]); err == nil && aNum >= 0 && aNum <= 255 {
			if name, ok := hipAlgorithms[byte(aNum)]; ok {
				algName = name
			}
		}

		ctxStr := "HIP Record, Alg: " + algName + ", HIT: " + hit
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   pubKey,
			Context: ctxStr,
		})

		for _, rv := range rendezvousers {
			rv = strings.TrimSuffix(rv, ".")
			if rv != "" {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "domain",
					Value:   rv,
					Context: "HIP Rendezvous Server",
				})
			}
		}
	}

	return execution
}
