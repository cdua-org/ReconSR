package dns

import (
	"context"
	"strings"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getHINFOData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_hinfo")

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	log.Printf("get_hinfo target=%q", target)

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 13, nil)
	if err != nil {
		modutil.SetError(&exec, "hinfo lookup failed: %v", err)
		log.Printf("get_hinfo error: %v", err)
		return exec
	}

	log.Printf("get_hinfo target=%q records=%d", target, len(records))

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "hinfo",
			Category: "property",
			Value:    rec,
			Context:  "Hardware & OS Info (HINFO)",
		})

		parts := strings.Fields(rec)
		if len(parts) >= 2 {
			cpu := strings.Trim(parts[0], "\"")
			osStr := strings.Trim(strings.Join(parts[1:], " "), "\"")

			if cpu != "" && cpu != "ANY" && !strings.Contains(cpu, "cloudflare") {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "hinfo",
					Category: "property",
					Value:    cpu,
					Context:  "HINFO Extracted CPU",
				})
			}
			if osStr != "" && osStr != "ANY" && !strings.Contains(osStr, "cloudflare") {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "hinfo",
					Category: "property",
					Value:    osStr,
					Context:  "HINFO Extracted OS",
				})
			}
		}
	}

	return exec
}
