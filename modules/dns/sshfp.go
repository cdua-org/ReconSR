package dns

import (
	"context"
	"encoding/hex"
	"fmt"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var sshfpAlgorithm = map[byte]string{
	1: constants.AlgRSA,
	2: constants.AlgDSA,
	3: constants.AlgECDSA,
	4: constants.AlgEd25519SSH,
	6: constants.AlgEd448SSH,
}

var sshfpFPType = map[byte]string{
	1: constants.DigestSHA1,
	2: constants.DigestSHA256,
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

func getSSHFPData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetSSHFP)
	log.Printf("%s query_start target=%q", constants.FuncGetSSHFP, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 44, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetSSHFP, target, err)
		modutil.SetError(&exec, "sshfp lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := parseSSHFP(rec)

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSSHFP,
			Category: constants.CategoryProperty,
			Value:    parsed,
			LocalID:  gen.NextID(),
		})
	}

	log.Printf("%s success target=%q records=%d", constants.FuncGetSSHFP, target, len(records))
	return exec
}
