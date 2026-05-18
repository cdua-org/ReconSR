package dns

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getIPData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetIP)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	log.Printf("%s query_start target=%q", constants.FuncGetIP, target)

	ips, raw, err := resolver.ResolveIP(queryCtx, target)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_ip err=%v", constants.FuncGetIP, target, err)
		modutil.SetError(&exec, "dns lookup failed: %v", err)
		return exec
	}

	log.Printf("%s success target=%q ips=%d", constants.FuncGetIP, target, len(ips))

	for _, ipStr := range ips {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeIP,
			Category: constants.CategoryNode,
			Value:    ipStr,
			Context:  "A/AAAA Record",
		})
	}

	modutil.SetRawFallback(&exec, raw, ips, ", ")

	return exec
}
