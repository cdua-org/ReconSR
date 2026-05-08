package dns

import (
	"context"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func parseNAPTRRecord(raw string) string {
	if strings.HasPrefix(raw, "\\# ") {
		return raw
	}
	return raw
}

func parseNativeNAPTR(parsed string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range parsed {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func extractNAPTRServiceAndReplacement(parsed string) (service, replacement string, ok bool) {
	parts := parseNativeNAPTR(parsed)
	if len(parts) < 5 {
		return "", "", false
	}

	service = strings.Trim(parts[3], "\"")
	replacement = parts[len(parts)-1]
	if replacement == service {
		return service, "", true
	}

	return service, replacement, true
}

func normalizeNAPTRTarget(replacement string) (normalizedTarget, scopeTarget string, ok bool) {
	replacement = strings.TrimSpace(strings.TrimSuffix(replacement, "."))
	if replacement == "" || replacement == "." || strings.ContainsAny(replacement, " \"") {
		return "", "", false
	}

	if res, err := validator.Validate(constants.TypeDomain, replacement); err == nil {
		return res.Value, res.Value, true
	}

	labels := strings.Split(replacement, ".")
	if len(labels) < 4 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return "", "", false
	}

	baseDomain := strings.Join(labels[2:], ".")
	res, err := validator.Validate(constants.TypeDomain, baseDomain)
	if err != nil {
		return "", "", false
	}

	return labels[0] + "." + labels[1] + "." + res.Value, res.Value, true
}

func buildNAPTRServiceResult(parsed, service string) schema.ModuleResult {
	return schema.ModuleResult{
		Type:     constants.TypeNAPTR,
		Category: constants.CategoryProperty,
		Value:    service,
		Context:  "NAPTR Service",
		Source: &schema.EntityRef{
			Type:  constants.TypeNAPTR,
			Value: parsed,
		},
	}
}

func buildNAPTRTargetResult(source *schema.EntityRef, target, replacement string) *schema.ModuleResult {
	normalizedTarget, scopeTarget, ok := normalizeNAPTRTarget(replacement)
	if !ok {
		log.Printf("get_naptr skipping invalid replacement target=%q entity=%q", target, replacement)
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(scopeTarget, target)

	return &schema.ModuleResult{
		Type:       constants.TypeNAPTRTarget,
		Category:   constants.CategoryNode,
		Value:      normalizedTarget,
		Context:    "Replacement Target",
		OutOfScope: isOOS,
		Source:     source,
	}
}

func getNAPTRData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetNAPTR)

	log.Printf("get_naptr starting query for target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 35, nil)
	if err != nil {
		log.Printf("get_naptr error for target=%q: %v", target, err)
		modutil.SetError(&exec, "naptr lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := parseNAPTRRecord(rec)
		rawResult := schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed,
			Context:  "NAPTR Record",
		}
		exec.Results = append(exec.Results, rawResult)

		if strings.HasPrefix(parsed, "\\# ") {
			continue
		}

		svc, replacement, ok := extractNAPTRServiceAndReplacement(parsed)
		if !ok {
			continue
		}

		targetSource := &schema.EntityRef{Type: rawResult.Type, Value: rawResult.Value}
		if svc != "" {
			serviceResult := buildNAPTRServiceResult(parsed, svc)
			exec.Results = append(exec.Results, serviceResult)
			targetSource = &schema.EntityRef{Type: serviceResult.Type, Value: serviceResult.Value}
		}

		targetResult := buildNAPTRTargetResult(targetSource, target, replacement)
		if targetResult == nil {
			continue
		}

		log.Printf("get_naptr target=%q entity=%q oos=%v", target, targetResult.Value, targetResult.OutOfScope)
		exec.Results = append(exec.Results, *targetResult)
	}

	log.Printf("get_naptr completed for target=%q results=%d", target, len(exec.Results))

	return exec
}
