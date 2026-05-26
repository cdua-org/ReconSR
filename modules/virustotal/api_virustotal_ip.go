package virustotal

import (
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *module) extractIPMetadata(attr map[string]any, target string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	tags := extractVTTags(attr)
	for _, tag := range tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tag,
			LocalID:  gen.NextID(),
		})
	}

	if asn, ok := formatVTInt(attr["asn"]); ok {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeASN,
			Category: constants.CategoryNode,
			Value:    asn,
			LocalID:  gen.NextID(),
		})
	}

	if network, ok := attr["network"].(string); ok {
		appendVTProperty(exec, constants.TypeCIDR, network, "Network CIDR for "+target, nil, gen)
	}

	if asOwner, ok := attr["as_owner"].(string); ok {
		appendVTProperty(exec, constants.TypeOrganization, asOwner, "AS Owner for "+target, nil, gen)
	}

	var geoParts []string
	if country, ok := attr["country"].(string); ok && country != "" {
		geoParts = append(geoParts, "Country: "+country)
	}
	if continent, ok := attr["continent"].(string); ok && continent != "" {
		geoParts = append(geoParts, "Continent: "+continent)
	}
	if len(geoParts) > 0 {
		appendVTProperty(exec, constants.TypeGeo, strings.Join(geoParts, " | "), "Geo Location for "+target, nil, gen)
	}

	if jarm, ok := attr["jarm"].(string); ok {
		appendVTProperty(exec, constants.TypeJARM, jarm, "JARM for "+target, nil, gen)
	}

	if lastUpdateRaw, ok := attr["last_modification_date"].(float64); ok {
		formattedDate := time.Unix(int64(lastUpdateRaw), 0).UTC().Format(time.RFC3339)
		appendVTProperty(exec, constants.TypeLastUpdate, formattedDate, "Last Update for "+target, nil, gen)
	}

	m.extractThreatScore(attr, constants.TypeIP, target, nil, exec, gen)
}

func (m *module) extractIPResolution(item map[string]any, _ string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	attr, ok := item["attributes"].(map[string]any)
	if !ok {
		return
	}

	host, ok := attr["host_name"].(string)
	if !ok {
		return
	}

	validated, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Context:  "VirusTotal Passive DNS",
		Tags:     []string{constants.TagPDNS},
		LocalID:  gen.NextID(),
	})
}
