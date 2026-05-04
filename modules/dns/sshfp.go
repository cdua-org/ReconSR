package dns

import (
	"context"
	"encoding/hex"
	"fmt"

	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var sshfpAlgorithm = map[byte]string{
	1: "RSA",
	2: "DSA",
	3: "ECDSA",
	4: "Ed25519",
	6: "Ed448",
}

var sshfpFPType = map[byte]string{
	1: "SHA-1",
	2: "SHA-256",
}

func parseSSHFP(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 3)
	if !ok {
		return raw
	}

	alg := data[0]
	fpType := data[1]
	fp := hex.EncodeToString(data[2:])

	algName, ok := sshfpAlgorithm[alg]
	if !ok {
		algName = fmt.Sprintf("Unknown(%d)", alg)
	}

	fpName, ok := sshfpFPType[fpType]
	if !ok {
		fpName = fmt.Sprintf("Unknown(%d)", fpType)
	}

	return fmt.Sprintf("%s %s %s", algName, fpName, fp)
}

func getSSHFPData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_sshfp")
	log.Printf("get_sshfp target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 44, nil)
	if err != nil {
		log.Printf("get_sshfp error: %v", err)
		modutil.SetError(&exec, "sshfp lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := parseSSHFP(rec)

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "sshfp",
			Category: "property",
			Value:    parsed,
		})
	}

	log.Printf("get_sshfp target=%q records=%d", target, len(records))
	return exec
}
