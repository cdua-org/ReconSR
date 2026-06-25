package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
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

func parseCERT(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 5)
	if !ok {
		return raw
	}

	cType := uint16(data[0])<<8 | uint16(data[1])
	keyTag := uint16(data[2])<<8 | uint16(data[3])
	alg := data[4]
	certBase64 := base64.StdEncoding.EncodeToString(data[5:])

	return fmt.Sprintf("%d %d %d %s", cType, keyTag, alg, certBase64)
}

func getCERTData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetCERT)

	log.Printf("%s query_start target=%q", constants.FuncGetCERT, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolveRecordFunc(queryCtx, target, 37, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetCERT, target, err)
		modutil.SetError(&exec, "cert lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("%s success target=%q records=%d", constants.FuncGetCERT, target, len(records))

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

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCert,
			Category: constants.CategoryProperty,
			Value:    parts[3],
			Context:  "CERT Record, Type: " + cTypeName + ", KeyTag: " + keyTag + ", Alg: " + algName,
			LocalID:  gen.NextID(),
		})
	}

	return exec
}
