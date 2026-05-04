package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
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

func parseDNSKEY(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 5)
	if !ok {
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

func getDNSKEYData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_dnskey")

	log.Printf("get_dnskey target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 48, nil)
	if err != nil {
		log.Printf("get_dnskey error: %v", err)
		modutil.SetError(&exec, "dnskey lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("get_dnskey target=%q records=%d", target, len(records))

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
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "dnskey",
					Category: "property",
					Value:    parts[3],
					Context:  "DNSKEY KSK, Alg: " + algName,
				})
			case "256":
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "dnskey",
					Category: "property",
					Value:    parts[3],
					Context:  "DNSKEY ZSK, Alg: " + algName,
				})
			}
		}
	}

	return exec
}
