package dns

import (
	"context"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getHINFOData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetHINFO)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	log.Printf("%s query_start target=%q", constants.FuncGetHINFO, target)

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 13, nil)
	if err != nil {
		modutil.SetError(&exec, "hinfo lookup failed: %v", err)
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetHINFO, target, err)
		return exec
	}

	log.Printf("%s success target=%q records=%d", constants.FuncGetHINFO, target, len(records))

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := dnsutils.ParseHINFO(rec)
		if parsed == nil {
			continue
		}

		hinfoRes := schema.ModuleResult{
			Type:     constants.TypeHINFO,
			Category: constants.CategoryProperty,
			Value:    parsed.Formatted,
			Context:  "Hardware & OS Info (HINFO)",
		}
		exec.Results = append(exec.Results, hinfoRes)

		source := &schema.EntityRef{Type: hinfoRes.Type, Value: hinfoRes.Value}
		exec.Results = append(exec.Results, buildHINFOResults(parsed, source)...)
	}

	return exec
}

func buildHINFOResults(parsed *dnsutils.HINFORecord, source *schema.EntityRef) []schema.ModuleResult {
	var results []schema.ModuleResult
	if parsed.CPU != "" && parsed.CPU != "ANY" && !strings.Contains(parsed.CPU, "cloudflare") {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeHINFO,
			Category: constants.CategoryProperty,
			Value:    parsed.CPU,
			Context:  "HINFO Extracted CPU",
			Source:   source,
		})
	}
	if parsed.OS != "" && parsed.OS != "ANY" && !strings.Contains(parsed.OS, "cloudflare") {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeHINFO,
			Category: constants.CategoryProperty,
			Value:    parsed.OS,
			Context:  "HINFO Extracted OS",
			Source:   source,
		})
	}
	return results
}
