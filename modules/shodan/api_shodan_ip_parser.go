package shodan

import (
	"encoding/json"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIIP(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var payload shodanIPResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	extractIPDomains(exec, payload.Domains, payload.Tags)
	extractIPASN(exec, payload.ASN, payload.Tags)
	extractIPProperties(exec, &payload, payload.Tags, target)
	extractIPLastUpdate(exec, payload.LastUpdate, payload.Tags, target)
	extractIPHostnames(exec, payload.Hostnames, payload.Tags)
	extractIPBanners(exec, payload.Data, payload.Tags, target)
}

func extractIPDomains(exec *schema.ModuleExecution, domains, tags []string) {
	for _, domain := range domains {
		if val, err := validator.Validate(entityTypeDomain, domain); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     "shodan_domain",
				Category: resultCategoryNode,
				Value:    val.Value,
				Tags:     tags,
			})
		}
	}
}

func extractIPASN(exec *schema.ModuleExecution, asn string, tags []string) {
	if asn == "" {
		return
	}

	asnNumber := strings.TrimPrefix(strings.ToUpper(asn), "AS")
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     "asn",
		Category: resultCategoryNode,
		Value:    asnNumber,
		Tags:     tags,
	})
}

func extractIPProperties(exec *schema.ModuleExecution, payload *shodanIPResponse, tags []string, target string) {
	appendIPProperty(exec, "org", payload.Org, tags, "Organization for "+target)
	if !strings.EqualFold(payload.ISP, payload.Org) {
		appendIPProperty(exec, "isp", payload.ISP, tags, "ISP for "+target)
	}
	appendIPProperty(exec, "os", payload.OS, tags, "OS for "+target)
}

func appendIPProperty(exec *schema.ModuleExecution, resultType, value string, tags []string, context string) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Context:  context,
		Tags:     tags,
	})
}

func extractIPLastUpdate(exec *schema.ModuleExecution, lastUpdate string, tags []string, target string) {
	if lastUpdate == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultTypeLastUpdate,
		Category: resultCategoryProperty,
		Value:    lastUpdate,
		Context:  "Last Update for " + target,
		Tags:     tags,
	})
}

func extractIPHostnames(exec *schema.ModuleExecution, hostnames, tags []string) {
	for _, hostname := range hostnames {
		if hostname == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "ptr",
			Category: resultCategoryProperty,
			Value:    hostname,
			Tags:     tags,
		})
	}
}
