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

func getTXTData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetTXT)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup txt failed: %w", err)
		}
		return txts, nil
	}

	log.Printf("get_txt target=%q", target)

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 16, plainFallback)
	if err != nil {
		log.Printf("get_txt error: %v", err)
		modutil.SetError(&exec, "txt lookup failed: %v", err)
		return exec
	}

	log.Printf("get_txt target=%q records=%d", target, len(records))

	modutil.SetRawFallback(&exec, raw, records, "\n")

	var spfRecords []string
	var generalRecords []string

	for _, txt := range records {
		txt = strings.Trim(strings.TrimSpace(txt), "\"")
		if txt == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfRecords = append(spfRecords, txt)
		} else {
			generalRecords = append(generalRecords, txt)
		}
	}

	for _, spf := range spfRecords {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSPF,
			Category: constants.CategoryProperty,
			Value:    spf,
		})
	}

	for _, txt := range generalRecords {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTXT,
			Category: constants.CategoryProperty,
			Value:    txt,
		})
	}

	return exec
}
