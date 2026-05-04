package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func checkWildcard(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("check_wildcard")

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		modutil.SetError(&exec, "failed to generate random bytes: %v", err)
		return exec
	}

	testDomain := "recon-" + hex.EncodeToString(bytes) + "." + target

	log.Printf("check_wildcard target=%q", target)

	ips, raw, err := resolver.ResolveIP(queryCtx, testDomain)

	if err != nil {
		log.Printf("check_wildcard error: %v", err)
		modutil.SetError(&exec, "dns lookup failed: %v", err)
		return exec
	}

	log.Printf("check_wildcard target=%q ips=%d", target, len(ips))

	for _, ipStr := range ips {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "ip",
			Category: "node",
			Value:    ipStr,
			Context:  "Wildcard Record",
		})
	}

	modutil.SetRawFallback(&exec, raw, ips, ", ")

	return exec
}
