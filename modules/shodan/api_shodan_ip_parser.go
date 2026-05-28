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

	gen := modutil.NewLocalIDGenerator()

	appendShodanTagResults(exec, payload.Tags, gen)
	extractIPDomains(exec, payload.Domains, gen)
	extractIPASN(exec, payload.ASN, gen)
	extractIPProperties(exec, &payload, gen)
	extractIPLastUpdate(exec, payload.LastUpdate, gen)
	extractIPHostnames(exec, payload.Hostnames, gen)

	extractIPBanners(exec, payload.Data, gen)

	hasCVE := false
	for _, banner := range payload.Data {
		if banner.Artifacts != nil && len(banner.Artifacts.Vulns) > 0 {
			hasCVE = true
			break
		}
	}
	if hasCVE {
		if val, err := validator.Validate(constants.TypeIP, target); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Tags:     []string{constants.TagCVE},
				LocalID:  gen.NextID(),
			})
		}
	}
}

func extractIPDomains(exec *schema.ModuleExecution, domains []string, gen *modutil.LocalIDGenerator) {
	for _, domain := range domains {
		if val, err := validator.Validate(constants.TypeDomain, domain); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Tags:     []string{constants.TagReverseIP},
				LocalID:  gen.NextID(),
			})
		}
	}
}

func extractIPASN(exec *schema.ModuleExecution, asn string, gen *modutil.LocalIDGenerator) {
	if asn == "" {
		return
	}

	asnNumber := strings.TrimPrefix(strings.ToUpper(asn), "AS")
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeASN,
		Category: constants.CategoryNode,
		Value:    asnNumber,
		LocalID:  gen.NextID(),
	})
}

func extractIPProperties(exec *schema.ModuleExecution, payload *shodanIPResponse, gen *modutil.LocalIDGenerator) {
	appendIPProperty(exec, constants.TypeOrganization, payload.Org, gen)
	if !strings.EqualFold(payload.ISP, payload.Org) {
		appendIPProperty(exec, constants.TypeISP, payload.ISP, gen)
	}
	appendIPProperty(exec, constants.TypeOS, payload.OS, gen)
}

func appendIPProperty(exec *schema.ModuleExecution, resultType, value string, gen *modutil.LocalIDGenerator) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		LocalID:  gen.NextID(),
	})
}

func extractIPLastUpdate(exec *schema.ModuleExecution, lastUpdate string, gen *modutil.LocalIDGenerator) {
	if lastUpdate == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeLastUpdate,
		Category: constants.CategoryProperty,
		Value:    lastUpdate,
		LocalID:  gen.NextID(),
	})
}

func extractIPHostnames(exec *schema.ModuleExecution, hostnames []string, gen *modutil.LocalIDGenerator) {
	for _, hostname := range hostnames {
		appendReverseIPHostnameResult(exec, hostname, gen)
	}
}

func appendReverseIPHostnameResult(exec *schema.ModuleExecution, hostname string, gen *modutil.LocalIDGenerator) {
	if hostname == "" {
		return
	}

	if validated, err := validator.Validate(constants.TypeDomain, hostname); err == nil {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Tags:     []string{constants.TagReverseIP},
			LocalID:  gen.NextID(),
		})
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePTR,
		Category: constants.CategoryProperty,
		Value:    hostname,
		LocalID:  gen.NextID(),
	})
}
