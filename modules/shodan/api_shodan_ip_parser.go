package shodan

import (
	"encoding/json"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIIP(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var payload shodanIPResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	appendShodanTagResults(exec, payload.Tags)
	extractIPDomains(exec, payload.Domains)
	extractIPASN(exec, payload.ASN)
	extractIPProperties(exec, &payload, target)
	extractIPLastUpdate(exec, payload.LastUpdate, target)
	extractIPHostnames(exec, payload.Hostnames)
	extractIPBanners(exec, payload.Data, target)
}

func extractIPDomains(exec *schema.ModuleExecution, domains []string) {
	for _, domain := range domains {
		if val, err := validator.Validate(constants.TypeDomain, domain); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Tags:     []string{constants.TagReverseIP},
			})
		}
	}
}

func extractIPASN(exec *schema.ModuleExecution, asn string) {
	if asn == "" {
		return
	}

	asnNumber := strings.TrimPrefix(strings.ToUpper(asn), "AS")
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeASN,
		Category: constants.CategoryNode,
		Value:    asnNumber,
	})
}

func extractIPProperties(exec *schema.ModuleExecution, payload *shodanIPResponse, target string) {
	appendIPProperty(exec, constants.TypeOrganization, payload.Org, "Organization for "+target)
	if !strings.EqualFold(payload.ISP, payload.Org) {
		appendIPProperty(exec, constants.TypeISP, payload.ISP, "ISP for "+target)
	}
	appendIPProperty(exec, constants.TypeOS, payload.OS, "OS for "+target)
}

func appendIPProperty(exec *schema.ModuleExecution, resultType, value, context string) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  context,
	})
}

func extractIPLastUpdate(exec *schema.ModuleExecution, lastUpdate, target string) {
	if lastUpdate == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeLastUpdate,
		Category: constants.CategoryProperty,
		Value:    lastUpdate,
		Context:  "Last Update for " + target,
	})
}

func extractIPHostnames(exec *schema.ModuleExecution, hostnames []string) {
	for _, hostname := range hostnames {
		appendReverseIPHostnameResult(exec, hostname, "Shodan PTR")
	}
}

func appendReverseIPHostnameResult(exec *schema.ModuleExecution, hostname, context string) {
	if hostname == "" {
		return
	}

	if validated, err := validator.Validate(constants.TypeDomain, hostname); err == nil {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Context:  context,
			Tags:     []string{constants.TagReverseIP},
		})
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePTR,
		Category: constants.CategoryProperty,
		Value:    hostname,
		Context:  context,
	})
}
