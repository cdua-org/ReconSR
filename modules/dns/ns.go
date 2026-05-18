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

	log.Printf("%s query_start target=%q", constants.FuncGetNS, target)

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
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetNS, target, err)
		modutil.SetError(&exec, "ns lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFallback(&exec, raw, records, ", ")

	for _, rec := range records {
		result, ok := buildNSResult(rec, target)
		if !ok {
			continue
		}
		log.Printf("%s result_ns target=%q entity=%q oos=%v", constants.FuncGetNS, target, result.Value, result.OutOfScope)
		exec.Results = append(exec.Results, result)
	}

	if len(exec.Results) == 0 {
		return exec
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetNS, target, len(exec.Results))

	return exec
}

func buildNSResult(rawNS, target string) (schema.ModuleResult, bool) {
	ns := strings.TrimSuffix(strings.TrimSpace(rawNS), ".")
	if ns == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeDomain, ns)
	if err != nil {
		log.Printf("%s skip_invalid_ns target=%q entity=%q err=%v", constants.FuncGetNS, target, rawNS, err)
		return schema.ModuleResult{}, false
	}

	if res.Value == target {
		return schema.ModuleResult{}, false
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagNS},
		OutOfScope: isOOS,
	}, true
}
