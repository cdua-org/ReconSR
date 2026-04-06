package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

func getIPData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ip",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ips, raw, err := resolver.ResolveIP(ctx, target)
	if err != nil {
		errMsg := "dns lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	for _, ipStr := range ips {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "ip",
			Value:   ipStr,
			Context: "A/AAAA Record",
		})
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(ips) > 0 {
		// Fallback raw representation for Plain DNS which doesn't give us raw packet
		execution.RawData = strings.Join(ips, ", ")
	}

	return execution
}
