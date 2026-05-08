package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getNSData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetNS)

	log.Printf("get_ns starting query for target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		nss, err := r.LookupNS(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup ns failed: %w", err)
		}
		res := make([]string, 0, len(nss))
		for _, ns := range nss {
			res = append(res, ns.Host)
		}
		return res, nil
	}

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 2, plainFallback)
	if err != nil {
		log.Printf("get_ns error for target=%q: %v", target, err)
		modutil.SetError(&exec, "ns lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFallback(&exec, raw, records, ", ")

	for _, rec := range records {
		result, ok := buildNSResult(rec, target)
		if !ok {
			continue
		}
		log.Printf("get_ns target=%q entity=%q oos=%v", target, result.Value, result.OutOfScope)
		exec.Results = append(exec.Results, result)
	}

	if len(exec.Results) == 0 {
		return exec
	}

	log.Printf("get_ns completed for target=%q with %d results", target, len(exec.Results))

	return exec
}

func buildNSResult(rawNS, target string) (schema.ModuleResult, bool) {
	ns := strings.TrimSuffix(strings.TrimSpace(rawNS), ".")
	if ns == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeDomain, ns)
	if err != nil {
		log.Printf("get_ns skipping invalid ns target=%q entity=%q err=%v", target, rawNS, err)
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	return schema.ModuleResult{
		Type:       constants.TypeNS,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "NS Record",
		OutOfScope: isOOS,
	}, true
}
