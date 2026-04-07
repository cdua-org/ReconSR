package dns

import (
	"context"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getHINFOData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_hinfo",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 13, nil) // 13 is QTYPE for HINFO
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "Hardware & OS Info (HINFO)",
		})

		// Try to parse CPU and OS out of it playfully
		// According to RFC 1035, HINFO has CPU and OS separated by space.
		// If they include spaces they are usually enclosed in quotes.
		parts := strings.Fields(rec)
		if len(parts) >= 2 {
			cpu := strings.Trim(parts[0], "\"")
			osStr := strings.Trim(strings.Join(parts[1:], " "), "\"")

			// Do some sanity filtering so we don't output garbage
			if cpu != "" && cpu != "ANY" && !strings.Contains(cpu, "cloudflare") {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   cpu,
					Context: "HINFO Extracted CPU",
				})
			}
			if osStr != "" && osStr != "ANY" && !strings.Contains(osStr, "cloudflare") {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   osStr,
					Context: "HINFO Extracted OS",
				})
			}
		}
	}

	return execution
}
