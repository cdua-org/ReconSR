package dns

import (
	"context"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func normalizeNAPTRTarget(replacement string) (normalizedTarget, scopeTarget, resultType string, ok bool) {
	replacement = dnsutils.CleanSRVTarget(replacement)
	if replacement == "" || strings.ContainsAny(replacement, " \"") {
		return "", "", "", false
	}

	if res, err := validator.Validate(constants.TypeDomain, replacement); err == nil {
		return res.Value, res.Value, res.Type, true
	}

	return "", "", "", false
}

func buildNAPTRServiceResult(parsed, service string, gen *modutil.LocalIDGenerator) schema.ModuleResult {
	return schema.ModuleResult{
		Type:     constants.TypeNAPTR,
		Category: constants.CategoryProperty,
		Value:    service,
		Context:  "NAPTR Service",
		Source: &schema.EntityRef{
			Type:  constants.TypeNAPTR,
			Value: parsed,
		},
		LocalID: gen.NextID(),
	}
}

func buildNAPTRTargetResult(source *schema.EntityRef, target, replacement string, gen *modutil.LocalIDGenerator) *schema.ModuleResult {
	normalizedTarget, scopeTarget, resultType, ok := normalizeNAPTRTarget(replacement)
	if !ok || normalizedTarget == target {
		return nil
	}

	contextStr := "NAPTR Target"
	if replacement != normalizedTarget && replacement != normalizedTarget+"." {
		contextStr = "NAPTR Target (" + replacement + ")"
	}

	return &schema.ModuleResult{
		Type:       resultType,
		Category:   constants.CategoryNode,
		Value:      normalizedTarget,
		Tags:       []string{constants.TagNAPTR},
		Context:    contextStr,
		OutOfScope: orgdomain.IsOutOfScope(scopeTarget, target),
		Source:     source,
		LocalID:    gen.NextID(),
	}
}

func buildNAPTRRegexpResults(source *schema.EntityRef, regexpStr, regexpTarget string, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	if regexpStr == "" {
		return nil
	}
	results := []schema.ModuleResult{
		{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    regexpStr,
			Context:  "NAPTR Regexp",
			Source:   source,
			LocalID:  gen.NextID(),
		},
	}
	if regexpTarget != "" {
		results = append(results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    regexpTarget,
			Context:  "NAPTR Regexp Target",
			Source:   &schema.EntityRef{Type: constants.TypeNAPTR, Value: regexpStr},
			LocalID:  gen.NextID(),
		})
	}
	return results
}

func getNAPTRData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetNAPTR)

	log.Printf("%s query_start target=%q", constants.FuncGetNAPTR, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 35, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetNAPTR, target, err)
		modutil.SetError(&exec, "naptr lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := dnsutils.ParseNAPTR(rec)
		if parsed == nil {
			if strings.HasPrefix(rec, "\\# ") {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeNAPTR,
					Category: constants.CategoryProperty,
					Value:    rec,
					Context:  "NAPTR Record",
					LocalID:  gen.NextID(),
				})
			}
			continue
		}

		rawResult := schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed.Formatted,
			Context:  "NAPTR Record",
			LocalID:  gen.NextID(),
		}
		exec.Results = append(exec.Results, rawResult)

		targetSource := &schema.EntityRef{Type: rawResult.Type, Value: rawResult.Value}
		if parsed.Service != "" {
			serviceResult := buildNAPTRServiceResult(parsed.Formatted, parsed.Service, gen)
			exec.Results = append(exec.Results, serviceResult)
			targetSource = &schema.EntityRef{Type: serviceResult.Type, Value: serviceResult.Value}
		}

		if parsed.Regexp != "" {
			regexpResults := buildNAPTRRegexpResults(targetSource, parsed.Regexp, parsed.RegexpTarget, gen)
			exec.Results = append(exec.Results, regexpResults...)
		}

		targetResult := buildNAPTRTargetResult(targetSource, target, parsed.Replacement, gen)
		if targetResult == nil {
			continue
		}

		log.Printf("%s result_target target=%q entity=%q oos=%v", constants.FuncGetNAPTR, target, targetResult.Value, targetResult.OutOfScope)
		exec.Results = append(exec.Results, *targetResult)
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetNAPTR, target, len(exec.Results))

	return exec
}
