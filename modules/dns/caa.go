package dns

import (
	"context"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getCAAData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetCAA)

	log.Printf("%s query_start target=%q", constants.FuncGetCAA, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 257, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetCAA, target, err)
		modutil.SetError(&exec, "caa lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("%s success target=%q records=%d", constants.FuncGetCAA, target, len(records))

	for _, rec := range records {
		exec.Results = append(exec.Results, processCAARecord(rec, target)...)
	}

	return exec
}

func processCAARecord(data, target string) []schema.ModuleResult {
	normalized, tag, val, matched := dnsutils.ParseCAA(data)

	results := make([]schema.ModuleResult, 0, 2)
	caaResult := schema.ModuleResult{
		Type:     constants.TypeCAA,
		Category: constants.CategoryProperty,
		Value:    normalized,
	}
	results = append(results, caaResult)

	if !matched {
		return results
	}

	source := &schema.EntityRef{Type: caaResult.Type, Value: caaResult.Value}

	switch tag {
	case "issue", "issuewild", "issuemail":
		if result, ok := buildCAAAuthorityResult(tag, val, target, source); ok {
			results = append(results, result)
		}
	case "iodef":
		if result, ok := buildCAAIodefEmailResult(val, source); ok {
			results = append(results, result)
		}
	}

	return results
}

func buildCAAAuthorityResult(tag, val, target string, source *schema.EntityRef) (schema.ModuleResult, bool) {
	domain := dnsutils.ExtractCAAAuthority(val)
	if domain == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeDomain, domain)
	if err != nil {
		log.Printf("%s skip_invalid_authority tag=%q entity=%q err=%v", constants.FuncGetCAA, tag, domain, err)
		return schema.ModuleResult{}, false
	}

	if res.Value == target {
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagCAA},
		Context:    "Authorized CA" + " (" + tag + ")",
		OutOfScope: true,
		Source:     source,
	}, true
}

func buildCAAIodefEmailResult(val string, source *schema.EntityRef) (schema.ModuleResult, bool) {
	email := dnsutils.ExtractCAAIodefEmail(val)
	if email == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeEmail, email)
	if err != nil {
		log.Printf("%s skip_invalid_iodef_email entity=%q err=%v", constants.FuncGetCAA, email, err)
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "CAA Violation Report",
		OutOfScope: true,
		Source:     source,
	}, true
}
