package shodan

import (
	"encoding/json"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIDomain(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var payload shodanDomainResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	for _, record := range payload.Data {
		processShodanDomainRecord(exec, record, target)
	}
}

func processShodanDomainRecord(exec *schema.ModuleExecution, record shodanDomainRecord, target string) {
	fqdn, ok := buildShodanFQDN(target, record.Subdomain)
	if !ok {
		return
	}

	source := appendShodanSubdomain(exec, fqdn, target)
	value := strings.TrimSpace(record.Value)
	if value == "" {
		return
	}

	processShodanDNSRecord(exec, record.Type, value, target, source)
}

func buildShodanFQDN(target, subdomain string) (string, bool) {
	fqdn := target
	if subdomain != "" && subdomain != "@" {
		fqdn = subdomain + "." + target
	}

	validated, err := validator.Validate(entityTypeDomain, fqdn)
	if err != nil {
		return "", false
	}

	return validated.Value, true
}

func appendShodanSubdomain(exec *schema.ModuleExecution, fqdn, target string) *schema.EntityRef {
	if fqdn == target {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       resultTypeSubdomain,
		Category:   resultCategoryNode,
		Value:      fqdn,
		Context:    "Shodan DNS",
		OutOfScope: orgdomain.IsOutOfScope(fqdn, target),
	})

	return &schema.EntityRef{Type: resultTypeSubdomain, Value: fqdn}
}

func processShodanDNSRecord(exec *schema.ModuleExecution, recordType, value, target string, source *schema.EntityRef) {
	switch recordType {
	case "A", "AAAA":
		appendShodanIPResult(exec, value, source)
	case "CNAME":
		appendShodanDomainNode(exec, "cname", value, "CNAME Target", target, source)
	case "MX":
		appendShodanDomainNode(exec, "mx", value, "MX Target", target, source)
	case "NS":
		appendShodanDomainNode(exec, "ns", value, "NS Target", target, source)
	case "TXT":
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "txt",
			Category: resultCategoryProperty,
			Value:    value,
			Source:   source,
		})
	}
}

func appendShodanIPResult(exec *schema.ModuleExecution, value string, source *schema.EntityRef) {
	validated, err := validator.Validate(entityTypeIP, value)
	if err != nil {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: resultCategoryNode,
		Value:    validated.Value,
		Context:  "Resolved IP",
		Source:   source,
	})
}

func appendShodanDomainNode(exec *schema.ModuleExecution, resultType, value, context, target string, source *schema.EntityRef) {
	validated, err := validator.Validate(entityTypeDomain, value)
	if err != nil {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       resultType,
		Category:   resultCategoryNode,
		Value:      validated.Value,
		Context:    context,
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     source,
	})
}
