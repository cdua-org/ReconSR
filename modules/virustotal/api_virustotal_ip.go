package virustotal

import (
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func (m *module) extractIPMetadata(attr map[string]any, target string, exec *schema.ModuleExecution) {
	tags := extractVTTags(attr)

	if asn, ok := formatVTInt(attr["asn"]); ok {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeASN,
			Category: constants.CategoryNode,
			Value:    asn,
			Tags:     tags,
		})
	}

	if network, ok := attr["network"].(string); ok {
		appendVTProperty(exec, constants.TypeCIDR, network, "Network CIDR for "+target, tags, nil)
	}

	if asOwner, ok := attr["as_owner"].(string); ok {
		appendVTProperty(exec, constants.TypeOrg, asOwner, "AS Owner for "+target, tags, nil)
	}

	var geoParts []string
	if country, ok := attr["country"].(string); ok && country != "" {
		geoParts = append(geoParts, "Country: "+country)
	}
	if continent, ok := attr["continent"].(string); ok && continent != "" {
		geoParts = append(geoParts, "Continent: "+continent)
	}
	if len(geoParts) > 0 {
		appendVTProperty(exec, constants.TypeGeo, strings.Join(geoParts, " | "), "Geo Location for "+target, tags, nil)
	}

	if jarm, ok := attr["jarm"].(string); ok {
		appendVTProperty(exec, constants.TypeJARM, jarm, "JARM for "+target, tags, nil)
	}

	if lastUpdateRaw, ok := attr["last_modification_date"].(float64); ok {
		formattedDate := time.Unix(int64(lastUpdateRaw), 0).UTC().Format(time.RFC3339)
		appendVTProperty(exec, constants.TypeLastUpdate, formattedDate, "Last Update for "+target, tags, nil)
	}

	m.extractThreatScore(attr, nil, exec)
}

func (m *module) extractIPResolution(item map[string]any, target string, exec *schema.ModuleExecution) {
	attr, ok := item["attributes"].(map[string]any)
	if !ok {
		return
	}

	host, ok := attr["host_name"].(string)
	if !ok {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePDNSRecord,
		Category: constants.CategoryProperty,
		Value:    host,
		Context:  "VirusTotal Passive DNS",
		Source: &schema.EntityRef{
			Type:  constants.TypeIP,
			Value: target,
		},
	})
}
