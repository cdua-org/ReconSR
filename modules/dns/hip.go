package dns

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
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

func parseHIP(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 4)
	if !ok {
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

	return fmt.Sprintf("%d %s %s", alg, strings.ToUpper(hit), pubKeyBase64)
}

func getHIPData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_hip")
	log.Printf("get_hip target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 55, nil)
	if err != nil {
		log.Printf("get_hip error: %v", err)
		modutil.SetError(&exec, "hip lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		exec.Results = append(exec.Results, buildHIPResults(parseHIP(rec), target)...)
	}

	log.Printf("get_hip target=%q records=%d", target, len(records))
	return exec
}

func buildHIPResults(parsed, target string) []schema.ModuleResult {
	parts := strings.Fields(parsed)
	if len(parts) < 3 {
		return nil
	}

	algName := parts[0]
	hit := parts[1]
	pubKey := parts[2]

	if aNum, err := strconv.Atoi(parts[0]); err == nil && aNum >= 0 && aNum <= 255 {
		if name, ok := hipAlgorithms[byte(aNum)]; ok {
			algName = name
		}
	}

	ctxStr := "HIP Record, Alg: " + algName + ", HIT: " + hit
	results := []schema.ModuleResult{{
		Type:     "hip",
		Category: "property",
		Value:    pubKey,
		Context:  ctxStr,
	}}

	hipSource := &schema.EntityRef{Type: "hip", Value: pubKey}
	for _, rv := range parts[3:] {
		result := buildHIPRendezvousResult(rv, target, hipSource)
		if result == nil {
			continue
		}
		results = append(results, *result)
	}

	return results
}

func buildHIPRendezvousResult(rawRV, target string, hipSource *schema.EntityRef) *schema.ModuleResult {
	rv := strings.TrimSuffix(rawRV, ".")
	if rv == "" {
		return nil
	}

	res, err := validator.Validate("domain", rv)
	if err != nil {
		log.Printf("get_hip skipping invalid rendezvous target=%q rv=%q err=%v", target, rv, err)
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("get_hip target=%q rv=%q oos=%v", target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       "hip_server",
		Category:   "node",
		Value:      res.Value,
		Context:    "HIP Rendezvous Server",
		OutOfScope: isOOS,
		Source:     hipSource,
	}
}
