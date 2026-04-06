package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

func getDomainKeyData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_domainkey",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	domainkeyTarget := "_domainkey." + target

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, domainkeyTarget)
		if err != nil {
			return nil, fmt.Errorf("plain lookup domainkey failed: %w", err)
		}
		return txts, nil
	}

	// QTYPE 16 is TXT
	records, raw, err := resolver.ResolveRecord(ctx, domainkeyTarget, 16, plainFallback)
	if err != nil {
		errMsg := "domainkey lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(records) > 0 {
		execution.RawData = strings.Join(records, ", ")
	}

	for _, rec := range records {
		rec = strings.Trim(strings.TrimSpace(rec), "\"")
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "Old DomainKey Record: " + domainkeyTarget,
		})
	}

	return execution
}
