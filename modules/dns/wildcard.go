package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

func checkWildcard(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "check_wildcard",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		errMsg := "failed to generate random bytes: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	testDomain := "recon-" + hex.EncodeToString(bytes) + "." + target

	ips, raw, err := ResolveIP(ctx, testDomain)
	if err != nil {
		// ResolveIP returns an error only if all attempts (DoH + Plain) fail.
		// NXDOMAIN (no such host) does not return an error, it returns empty results.
		errMsg := "dns lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	for _, ipStr := range ips {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "ip",
			Value:   ipStr,
			Context: "Wildcard Record",
		})
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(ips) > 0 {
		// Fallback raw representation for Plain DNS which doesn't give us raw packet
		execution.RawData = strings.Join(ips, ", ")
	}

	return execution
}
