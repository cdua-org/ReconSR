package hunterio

import (
	"embed"
	"encoding/json"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/domain_search_b2b.json
var demoData embed.FS

// getDomainSearchDemo is a demo function that loads a local JSON fixture
// instead of querying the Hunter.io API when the "demo-api-key" is used.
func (m *module) getDomainSearchDemo(exec *schema.ModuleExecution, targetType, targetValue string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	if !m.demoFired.CompareAndSwap(false, true) {
		dlog.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetHunterioDomainSearch, targetValue)
		return *exec
	}

	dlog.Printf("%s start stage=demo_mode", constants.FuncGetHunterioDomainSearch)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for Hunter.io (API key not configured)",
		LocalID:  gen.NextID(),
	})

	data, err := demoData.ReadFile("testdata/domain_search_b2b.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return *exec
	}

	var parsedResp apiDomainSearchResponse
	if err := json.Unmarshal(data, &parsedResp); err != nil {
		modutil.SetError(exec, "unmarshal fixture err: %v", err)
		return *exec
	}

	if len(parsedResp.Errors) > 0 {
		dlog.Printf("%s success stage=demo_error parsed_errors=%d", constants.FuncGetHunterioDomainSearch, len(parsedResp.Errors))
		appendAPIErrorResult(exec, 429, data, gen)
		return *exec
	}

	dlog.Printf("%s success stage=demo_parsed parsed_emails=%d", constants.FuncGetHunterioDomainSearch, len(parsedResp.Data.Emails))

	domainForScope := targetValue
	if targetType == constants.TypeOrganization && parsedResp.Data.Domain != "" {
		domainForScope = parsedResp.Data.Domain
	}

	appendDomainProperties(exec, &parsedResp, gen)
	results := extractEmails(&parsedResp, domainForScope, gen)
	exec.Results = append(exec.Results, results...)

	for _, ld := range parsedResp.Data.LinkedDomains {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       constants.TypeDomain,
			Value:      ld,
			Tags:       []string{constants.TagLinked},
			OutOfScope: orgdomain.IsOutOfScope(ld, domainForScope),
			Applied:    true,
			LocalID:    gen.NextID(),
		})
	}

	modutil.SetRawFromBytes(exec, data)

	return *exec
}
