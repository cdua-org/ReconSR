package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dsDigestTypes = map[byte]string{
	1: constants.DigestSHA1,
	2: constants.DigestSHA256,
	3: constants.DigestGOSTR341194,
	4: constants.DigestSHA384,
}

func parseDS(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 5)
	if !ok {
		return raw
	}

	keyTag := uint16(data[0])<<8 | uint16(data[1])
	alg := data[2]
	digestType := data[3]
	digest := hex.EncodeToString(data[4:])

	return fmt.Sprintf("%d %d %d %s", keyTag, alg, digestType, strings.ToUpper(digest))
}

func getDSData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDS)

	log.Printf("%s query_start target=%q", constants.FuncGetDS, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolveRecordFunc(queryCtx, target, 43, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetDS, target, err)
		modutil.SetError(&exec, "ds lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("%s success target=%q records=%d", constants.FuncGetDS, target, len(records))

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

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDS,
			Category: constants.CategoryProperty,
			Value:    parts[3],
			Context:  "DS Record, KeyTag: " + keyTag + ", Alg: " + algName + ", Hash: " + digestName,
			LocalID:  gen.NextID(),
		})
	}

	return exec
}
