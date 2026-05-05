package shodan

import (
	"encoding/json"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIIP(exec *schema.ModuleExecution, rawBody []byte) {
	var payload shodanIPResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	extractIPDomains(exec, payload.Domains, payload.Tags)
	extractIPASN(exec, payload.ASN, payload.Tags)
	extractIPProperties(exec, &payload, payload.Tags)
	extractIPLastUpdate(exec, payload.LastUpdate, payload.Tags)
	extractIPHostnames(exec, payload.Hostnames, payload.Tags)
	extractIPBanners(exec, payload.Data, payload.Tags)
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

func extractIPProperties(exec *schema.ModuleExecution, payload *shodanIPResponse, tags []string) {
	appendIPProperty(exec, "org", payload.Org, tags)
	if !strings.EqualFold(payload.ISP, payload.Org) {
		appendIPProperty(exec, "isp", payload.ISP, tags)
	}
	appendIPProperty(exec, "os", payload.OS, tags)
}

func appendIPProperty(exec *schema.ModuleExecution, resultType, value string, tags []string) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Tags:     tags,
	})
}

func extractIPLastUpdate(exec *schema.ModuleExecution, lastUpdate string, tags []string) {
	if lastUpdate == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultTypeLastUpdate,
		Category: resultCategoryProperty,
		Value:    lastUpdate,
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
