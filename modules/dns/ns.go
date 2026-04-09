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

func getNSData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ns",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		nss, err := r.LookupNS(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup ns failed: %w", err)
		}
		var res []string
		for _, ns := range nss {
			res = append(res, ns.Host)
		}
		return res, nil
	}

	// QTYPE 2 is NS
	records, raw, err := resolver.ResolveRecord(ctx, target, 2, plainFallback)
	if err != nil {
		errMsg := "ns lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(records) > 0 {
		execution.RawData = strings.Join(records, ", ")
	}

	var nss []string
	for _, rec := range records {
		ns := strings.TrimSuffix(rec, ".")
		if ns != "" {
			nss = append(nss, ns)
		}
	}

	if len(nss) == 0 {
		return execution
	}

	for _, ns := range nss {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "domain",
			Value:   ns,
			Context: "NS Record",
		})
	}

	return execution
}
