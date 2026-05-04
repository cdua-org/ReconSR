package dns

import (
	"context"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getIPData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_ip")

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	log.Printf("get_ip target=%q", target)

	ips, raw, err := resolver.ResolveIP(queryCtx, target)
	if err != nil {
		log.Printf("get_ip error: %v", err)
		modutil.SetError(&exec, "dns lookup failed: %v", err)
		return exec
	}

	log.Printf("get_ip target=%q ips=%d", target, len(ips))

	for _, ipStr := range ips {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "ip",
			Category: "node",
			Value:    ipStr,
			Context:  "A/AAAA Record",
		})
	}

	modutil.SetRawFallback(&exec, raw, ips, ", ")

	return exec
}
