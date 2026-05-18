package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
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

	log.Printf("%s query_start target=%q", constants.FuncGetTXT, target)

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 16, plainFallback)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetTXT, target, err)
		modutil.SetError(&exec, "txt lookup failed: %v", err)
		return exec
	}

	log.Printf("%s success target=%q records=%d", constants.FuncGetTXT, target, len(records))

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

		spfRef := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}
		exec.Results = append(exec.Results, buildSPFEntityResults(spfRef, spf, target)...)
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

func buildSPFEntityResults(source *schema.EntityRef, spf, target string) []schema.ModuleResult {
	entities := dnsutils.ParseSPF(spf)
	if len(entities) == 0 {
		return nil
	}

	results := make([]schema.ModuleResult, 0, len(entities))
	for _, ent := range entities {
		result, ok := buildSPFEntityResult(source, ent, target)
		if ok {
			results = append(results, result)
		}
	}
	return results
}

func buildSPFEntityResult(source *schema.EntityRef, ent dnsutils.SPFEntity, target string) (schema.ModuleResult, bool) {
	switch ent.Kind {
	case dnsutils.SPFEntityIP4, dnsutils.SPFEntityIP6:
		return buildSPFIPResult(source, ent)
	case dnsutils.SPFEntityDomain:
		return buildSPFDomainResult(source, ent, target)
	default:
		return schema.ModuleResult{}, false
	}
}

func buildSPFIPResult(source *schema.EntityRef, ent dnsutils.SPFEntity) (schema.ModuleResult, bool) {
	validated, err := validator.Validate(constants.TypeIP, ent.Value)
	if err != nil {
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Tags:     []string{constants.TagSPF},
		Context:  "SPF " + ent.Mechanism,
		Source:   source,
	}, true
}

func buildSPFDomainResult(source *schema.EntityRef, ent dnsutils.SPFEntity, target string) (schema.ModuleResult, bool) {
	validated, err := validator.Validate(constants.TypeDomain, ent.Value)
	if err != nil {
		return schema.ModuleResult{}, false
	}

	if validated.Value == target {
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagSPF},
		Context:    "SPF " + ent.Mechanism,
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     source,
	}, true
}
