package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// sshfpAlgorithm maps SSHFP algorithm numbers to names (RFC 4255, 6594, 7479).
var sshfpAlgorithm = map[byte]string{
	1: "RSA",
	2: "DSA",
	3: "ECDSA",
	4: "Ed25519",
	6: "Ed448",
}

// sshfpFPType maps SSHFP fingerprint type numbers to names.
var sshfpFPType = map[byte]string{
	1: "SHA-1",
	2: "SHA-256",
}

// parseSSHFP decodes RFC 3597 wire format (\# <len> <hex>) for SSHFP records.
// Wire: 1 byte algorithm + 1 byte fingerprint type + fingerprint bytes.
func parseSSHFP(raw string) string {
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

func getSSHFPData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_sshfp",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 44, nil) // 44 is QTYPE for SSHFP
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseSSHFP(rec)

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parsed,
			Context: "SSH Fingerprint",
		})
	}

	return execution
}
