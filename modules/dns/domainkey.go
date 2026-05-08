package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getDomainKeyData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDomainKey)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	domainkeyTarget := domainKeyLabel + "." + target

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, domainkeyTarget)
		if err != nil {
			return nil, fmt.Errorf("plain lookup domainkey failed: %w", err)
		}
		return txts, nil
	}

	log.Printf("get_domainkey target=%q", target)

	records, raw, err := resolver.ResolveRecord(queryCtx, domainkeyTarget, 16, plainFallback)
	if err != nil {
		log.Printf("get_domainkey error: %v", err)
		modutil.SetError(&exec, "domainkey lookup failed: %v", err)
		return exec
	}

	log.Printf("get_domainkey target=%q records=%d", target, len(records))

	modutil.SetRawFallback(&exec, raw, records, ", ")

	for _, rec := range records {
		rec = strings.Trim(strings.TrimSpace(rec), "\"")
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDomainKey,
			Category: constants.CategoryProperty,
			Value:    rec,
			Context:  "Old DomainKey Record: " + domainkeyTarget,
		})
	}

	return exec
}
