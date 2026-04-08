package dns

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var ipseckeyAlgorithms = map[byte]string{
	1: "DSA",
	2: "RSA",
	3: "ECDSA",
}

var ipseckeyGatewayTypes = map[byte]string{
	0: "None",
	1: "IPv4",
	2: "IPv6",
	3: "Domain",
}

// parseIPSECKEY decodes RFC 3597 wire format (\# <len> <hex>) for IPSECKEY records (RFC 4025).
// Format: 1b Precedence, 1b GW Type, 1b Algorithm, variable GW, variable Public Key
func parseIPSECKEY(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 3 {
		return raw
	}

	precedence := data[0]
	gwType := data[1]
	alg := data[2]

	var gw string
	var pubKeyBytes []byte

	offset := 3
	switch gwType {
	case 0:
		gw = "."
		pubKeyBytes = data[offset:]
	case 1:
		if len(data) < offset+4 {
			return raw
		}
		gw = net.IP(data[offset : offset+4]).String()
		pubKeyBytes = data[offset+4:]
	case 2:
		if len(data) < offset+16 {
			return raw
		}
		gw = net.IP(data[offset : offset+16]).String()
		pubKeyBytes = data[offset+16:]
	case 3:
		// Basic wire format domain extraction. We search for the null byte terminator.
		nullIdx := offset
		for nullIdx < len(data) && data[nullIdx] != 0 {
			nullIdx++
		}
		if nullIdx >= len(data) {
			return raw
		}
		// Skipping advanced decompression. Returning generic hex if it's compressed (to be safe).
		gw = "<wire_domain>"
		pubKeyBytes = data[nullIdx+1:]
	default:
		gw = "<unknown>"
		pubKeyBytes = data[offset:]
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	return fmt.Sprintf("%d %d %d %s %s", precedence, gwType, alg, gw, pubKeyBase64)
}

func mapIPSECKEYContext(precedence, gwTypeStr, algStr string) (ctx, gwTypeName string) {
	algName := algStr
	if aNum, err := strconv.Atoi(algStr); err == nil && aNum >= 0 && aNum <= 255 {
		if name, ok := ipseckeyAlgorithms[byte(aNum)]; ok {
			algName = name
		}
	}

	gwTypeName = gwTypeStr
	if gNum, err := strconv.Atoi(gwTypeStr); err == nil && gNum >= 0 && gNum <= 255 {
		if name, ok := ipseckeyGatewayTypes[byte(gNum)]; ok {
			gwTypeName = name
		}
	}

	ctx = "IPSECKEY Record, Precedence: " + precedence + ", Alg: " + algName + ", GW Type: " + gwTypeName
	return ctx, gwTypeName
}

func getIPSECKEYData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ipseckey",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 45, nil) // 45 is QTYPE for IPSECKEY
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseIPSECKEY(rec)

		parts := strings.Fields(parsed)
		if len(parts) < 5 {
			continue
		}

		precedence := parts[0]
		gwTypeStr := parts[1]
		algStr := parts[2]
		gateway := parts[3]
		pubKey := strings.Join(parts[4:], "")

		ctxStr, gwTypeName := mapIPSECKEYContext(precedence, gwTypeStr, algStr)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   pubKey,
			Context: ctxStr,
		})

		// Emit gateway if it's valid
		if gateway != "." && gateway != "<wire_domain>" && gateway != "<unknown>" {
			gwTypeOutput := "domain"
			if net.ParseIP(gateway) != nil {
				gwTypeOutput = "ip"
			}
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    gwTypeOutput,
				Value:   gateway,
				Context: "IPSECKEY Gateway (" + gwTypeName + ")",
			})
		}
	}

	return execution
}
