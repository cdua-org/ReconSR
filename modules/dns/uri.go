package dns

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getURIData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetURI)

	log.Printf("%s query_start target=%q", constants.FuncGetURI, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 256, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetURI, target, err)
		modutil.SetError(&exec, "uri lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("%s success target=%q records=%d", constants.FuncGetURI, target, len(records))

	for _, rec := range records {
		parsed := dnsutils.ParseURI(rec)
		if parsed == nil {
			continue
		}

		uriRes := schema.ModuleResult{
			Type:     constants.TypeURI,
			Category: constants.CategoryProperty,
			Value:    parsed.Formatted,
			Context:  "URI Record",
		}
		exec.Results = append(exec.Results, uriRes)

		source := &schema.EntityRef{Type: uriRes.Type, Value: uriRes.Value}
		exec.Results = append(exec.Results, buildURIResults(parsed, source)...)
	}

	return exec
}

func buildURIResults(parsed *dnsutils.URIRecord, source *schema.EntityRef) []schema.ModuleResult {
	var results []schema.ModuleResult
	if parsed.Target != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    parsed.Target,
			Context:  "URI Endpoint",
			Source:   source,
		})
	}
	return results
}
