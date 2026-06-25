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

func getDomainKeyData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDomainKey)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	domainkeyTarget := domainKeyLabel + "." + target

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := plainLookupTXT(fallbackCtx, r, domainkeyTarget)
		if err != nil {
			return nil, fmt.Errorf("plain lookup domainkey failed: %w", err)
		}
		return txts, nil
	}

	log.Printf("%s query_start target=%q", constants.FuncGetDomainKey, target)

	records, raw, err := resolveRecordFunc(queryCtx, domainkeyTarget, 16, plainFallback)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetDomainKey, target, err)
		modutil.SetError(&exec, "domainkey lookup failed: %v", err)
		return exec
	}

	log.Printf("%s success target=%q records=%d", constants.FuncGetDomainKey, target, len(records))

	modutil.SetRawFallback(&exec, raw, records, ", ")

	for _, rec := range records {
		rec = strings.Trim(strings.TrimSpace(rec), "\"")
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDomainKey,
			Category: constants.CategoryProperty,
			Value:    rec,
			Context:  "Old DomainKey Record: " + domainkeyTarget,
			LocalID:  gen.NextID(),
		})
	}

	return exec
}
