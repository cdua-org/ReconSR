package virustotal

import (
	"fmt"
	"sort"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func appendFileThreatScore(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	stats, ok := attr[vtKeyAnalysisStats].(map[string]any)
	if !ok {
		return
	}

	var malicious, suspicious int
	if mVal, ok := stats[constants.TagMalicious].(float64); ok {
		malicious = int(mVal)
	}
	if sVal, ok := stats[constants.TagSuspicious].(float64); ok {
		suspicious = int(sVal)
	}

	if malicious == 0 && suspicious == 0 {
		return
	}

	if malicious > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeFileHash,
			Category: constants.CategoryProperty,
			Value:    hashRef.Value,
			Tags:     []string{constants.TagMalicious},
			LocalID:  gen.NextID(),
		})
	} else if suspicious > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeFileHash,
			Category: constants.CategoryProperty,
			Value:    hashRef.Value,
			Tags:     []string{constants.TagSuspicious},
			LocalID:  gen.NextID(),
		})
	}

	engines := extractEngines(attr)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeThreatScore,
		Category: constants.CategoryProperty,
		Value:    fmt.Sprintf("Malicious: %d, Suspicious: %d", malicious, suspicious),
		Context:  engines,
		Source:   hashRef,
		LocalID:  gen.NextID(),
	})
}

func appendFileThreatClassification(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	classification, ok := attr["popular_threat_classification"].(map[string]any)
	if !ok {
		return
	}

	if label, ok := classification["suggested_threat_label"].(string); ok && label != "" {
		appendVTProperty(exec, constants.TypeThreatType, label, "Threat Classification", hashRef, gen)
	}
}

func appendFileCategories(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	categories, ok := attr["popular_threat_category"].([]any)
	if !ok || len(categories) == 0 {
		return
	}

	for _, raw := range categories {
		if cat, ok := raw.(string); ok && cat != "" {
			appendVTProperty(exec, constants.TypeCategory, cat, "Threat Category", hashRef, gen)
		}
	}
}

func appendFileYaraRules(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	results, ok := attr["crowdsourced_yara_results"].([]any)
	if !ok || len(results) == 0 {
		return
	}

	for _, raw := range results {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ruleName, ok := entry["rule_name"].(string)
		if !ok || ruleName == "" {
			continue
		}

		var parts []string
		parts = append(parts, ruleName)
		if author, ok := entry["author"].(string); ok && author != "" {
			parts = append(parts, "Author: "+author)
		}

		parentVal := strings.Join(parts, " | ")
		parentID := gen.NextID()

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeYaraRule,
			Category: constants.CategoryProperty,
			Value:    parentVal,
			Source:   hashRef,
			LocalID:  parentID,
		})

		parentRef := &schema.EntityRef{Type: constants.TypeYaraRule, Value: parentVal, LocalID: parentID}

		if desc, ok := entry["description"].(string); ok && desc != "" {
			desc = strings.ReplaceAll(desc, "\r", " ")
			desc = strings.ReplaceAll(desc, "\n", " ")
			desc = strings.Join(strings.Fields(desc), " ")
			appendVTProperty(exec, constants.TypeDescription, desc, "", parentRef, gen)
		}
		if src, ok := entry["source"].(string); ok && src != "" {
			appendVTProperty(exec, constants.TypeRule, src, "", parentRef, gen)
		}
	}
}

func appendFileSigmaRules(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	results, ok := attr["sigma_analysis_results"].([]any)
	if !ok || len(results) == 0 {
		return
	}

	for _, raw := range results {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		title, ok := entry["rule_title"].(string)
		if !ok || title == "" {
			continue
		}

		var parts []string
		parts = append(parts, title)
		if level, ok := entry["rule_level"].(string); ok && level != "" {
			parts = append(parts, "Severity: "+level)
		}
		if author, ok := entry["rule_author"].(string); ok && author != "" {
			parts = append(parts, "Author: "+author)
		}

		parentVal := strings.Join(parts, " | ")
		parentID := gen.NextID()

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSigmaRule,
			Category: constants.CategoryProperty,
			Value:    parentVal,
			Source:   hashRef,
			LocalID:  parentID,
		})

		parentRef := &schema.EntityRef{Type: constants.TypeSigmaRule, Value: parentVal, LocalID: parentID}

		if desc, ok := entry["rule_description"].(string); ok && desc != "" {
			desc = strings.ReplaceAll(desc, "\r", " ")
			desc = strings.ReplaceAll(desc, "\n", " ")
			desc = strings.Join(strings.Fields(desc), " ")
			appendVTProperty(exec, constants.TypeDescription, desc, "", parentRef, gen)
		}
		if src, ok := entry["rule_source"].(string); ok && src != "" {
			appendVTProperty(exec, constants.TypeSource, src, "", parentRef, gen)
		}
		extractSigmaMatchContext(exec, entry, parentRef, gen)
	}
}

func extractSigmaMatchContext(exec *schema.ModuleExecution, entry map[string]any, parentRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	matchCtx, ok := entry["match_context"].([]any)
	if !ok || len(matchCtx) == 0 {
		return
	}

	for _, ctxRaw := range matchCtx {
		ctxObj, ok := ctxRaw.(map[string]any)
		if !ok {
			continue
		}
		values, ok := ctxObj["values"].(map[string]any)
		if !ok {
			continue
		}

		if formatted := formatSigmaMatchContext(values); formatted != "" {
			appendVTProperty(exec, constants.TypeMatchContext, formatted, "", parentRef, gen)
		}
	}
}

func formatSigmaMatchContext(values map[string]any) string {
	var keys []string
	strVals := make(map[string]string)
	for k, v := range values {
		var strVal string
		if s, ok := v.(string); ok && s != "" {
			strVal = s
		} else if s := fmt.Sprintf("%v", v); s != "" {
			strVal = s
		}
		if strVal != "" {
			keys = append(keys, k)
			strVals[k] = strVal
		}
	}

	if len(keys) == 0 {
		return ""
	}

	sort.Slice(keys, getSigmaMatchContextSortFunc(keys))

	var ctxParts []string
	for _, k := range keys {
		ctxParts = append(ctxParts, fmt.Sprintf("%s: %s", k, strVals[k]))
	}

	return strings.Join(ctxParts, ", ")
}

func getSigmaMatchContextSortFunc(keys []string) func(i, j int) bool {
	priority := map[string]int{
		"EventID":           1,
		"Image":             2,
		"CommandLine":       3,
		"Protocol":          4,
		"SourceIp":          5,
		"SourcePort":        6,
		"SourceIsIpv6":      7,
		"DestinationIp":     8,
		"DestinationPort":   9,
		"DestinationIsIpv6": 10,
		"Initiated":         11,
	}
	return func(i, j int) bool {
		pi, oki := priority[keys[i]]
		pj, okj := priority[keys[j]]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return keys[i] < keys[j]
	}
}

func appendFileIDSAlerts(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	results, ok := attr["crowdsourced_ids_results"].([]any)
	if !ok || len(results) == 0 {
		return
	}

	for _, raw := range results {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		extractIDSAlert(exec, entry, hashRef, gen)
	}
}

func extractIDSAlert(exec *schema.ModuleExecution, entry map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	msg, ok := entry[vtKeyRuleMsg].(string)
	if !ok || msg == "" {
		return
	}

	var parts []string
	parts = append(parts, msg)
	if severity, ok := entry["alert_severity"].(string); ok && severity != "" {
		parts = append(parts, "Severity: "+severity)
	}

	parentVal := strings.Join(parts, " | ")
	parentID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeIDSAlert,
		Category: constants.CategoryProperty,
		Value:    parentVal,
		Source:   hashRef,
		LocalID:  parentID,
	})

	parentRef := &schema.EntityRef{Type: constants.TypeIDSAlert, Value: parentVal, LocalID: parentID}

	if rawRule, ok := entry["rule_raw"].(string); ok && rawRule != "" {
		appendVTProperty(exec, constants.TypeRawRule, rawRule, "", parentRef, gen)
	}
	if src, ok := entry["rule_source"].(string); ok && src != "" {
		appendVTProperty(exec, constants.TypeSource, src, "", parentRef, gen)
	}
	if ruleURL, ok := entry["rule_url"].(string); ok && ruleURL != "" {
		appendVTProperty(exec, constants.TypeRule, ruleURL, "", parentRef, gen)
	}
	if refs, ok := entry["rule_references"].([]any); ok {
		for _, r := range refs {
			if refStr, ok := r.(string); ok && refStr != "" {
				appendVTProperty(exec, constants.TypeReference, refStr, "", parentRef, gen)
			}
		}
	}
}

func appendFileMalwareConfig(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	config, ok := attr["malware_config"].(map[string]any)
	if !ok {
		return
	}

	var parts []string
	if family, ok := config["family"].(string); ok && family != "" {
		parts = append(parts, "Family: "+family)
	}
	if version, ok := config["version"].(string); ok && version != "" {
		parts = append(parts, "Version: "+version)
	}
	if c2Entries, ok := config["c2"].([]any); ok {
		c2Strs := make([]string, 0, len(c2Entries))
		for _, raw := range c2Entries {
			if s, ok := raw.(string); ok && s != "" {
				c2Strs = append(c2Strs, s)
			}
		}
		if len(c2Strs) > 0 {
			parts = append(parts, "C2: "+strings.Join(c2Strs, ", "))
		}
	}

	if len(parts) > 0 {
		appendVTProperty(exec, constants.TypeMalwareConfig, strings.Join(parts, " | "), "", hashRef, gen)
	}
}

func appendFileTags(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	tags := extractVTTags(attr)
	for _, tag := range tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tag,
			Source:   hashRef,
			LocalID:  gen.NextID(),
		})
	}
}

func appendFileSandboxVerdicts(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	verdicts, ok := attr[vtKeySandboxVerdict].(map[string]any)
	if !ok || len(verdicts) == 0 {
		return
	}

	for sandboxName, raw := range verdicts {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		cat, ok := entry[constants.KeyCategory].(string)
		if !ok || cat == "" || cat == "undetected" || cat == "harmless" {
			continue
		}

		var valueParts []string
		valueParts = append(valueParts, fmt.Sprintf("%s: %s", sandboxName, cat))

		if names, ok := entry["malware_names"].([]any); ok {
			nameStrs := make([]string, 0, len(names))
			for _, n := range names {
				if s, ok := n.(string); ok && s != "" {
					nameStrs = append(nameStrs, s)
				}
			}
			if len(nameStrs) > 0 {
				valueParts = append(valueParts, "("+strings.Join(nameStrs, ", ")+")")
			}
		}
		appendVTProperty(exec, constants.TypeSandboxVerdict, strings.Join(valueParts, " "), "", hashRef, gen)
	}
}

func appendFileReputation(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	rep, ok := attr[vtKeyReputation].(float64)
	if !ok || rep == 0 {
		return
	}

	reputation := int(rep)
	var value string
	switch {
	case reputation <= -5:
		value = fmt.Sprintf("%d (Malicious)", reputation)
	case reputation < 0:
		value = fmt.Sprintf("%d (Suspicious)", reputation)
	default:
		value = fmt.Sprintf("+%d (Safe/Benign)", reputation)
	}
	appendVTProperty(exec, constants.TypeReputation, value, "Community Reputation", hashRef, gen)
}
