package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func checkWildcard(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncCheckWildcard)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		log.Printf("%s error target=%q stage=generate_random_label err=%v", constants.FuncCheckWildcard, target, err)
		modutil.SetError(&exec, "failed to generate random bytes: %v", err)
		return exec
	}

	testDomain := "recon-" + hex.EncodeToString(bytes) + "." + target

	log.Printf("%s query_start target=%q", constants.FuncCheckWildcard, target)

	ips, raw, err := resolver.ResolveIP(queryCtx, testDomain)

	if err != nil {
		log.Printf("%s error target=%q test_domain=%q stage=resolve_ip err=%v", constants.FuncCheckWildcard, target, testDomain, err)
		modutil.SetError(&exec, "dns lookup failed: %v", err)
		return exec
	}

	log.Printf("%s success target=%q ips=%d", constants.FuncCheckWildcard, target, len(ips))

	for _, ipStr := range ips {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeIP,
			Category: constants.CategoryNode,
			Value:    ipStr,
			Context:  "Wildcard Record",
			LocalID:  gen.NextID(),
		})
	}

	modutil.SetRawFallback(&exec, raw, ips, ", ")

	return exec
}
