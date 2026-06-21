package virustotal

import (
	"fmt"
	"slices"
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
		extractYaraRule(exec, entry, hashRef, gen)
	}
}

func extractYaraRule(exec *schema.ModuleExecution, entry map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	ruleName, ok := entry["rule_name"].(string)
	if !ok || ruleName == "" {
		return
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
	if rulesetName, ok := entry["ruleset_name"].(string); ok && rulesetName != "" {
		appendVTProperty(exec, constants.TypeRule, "Ruleset: "+rulesetName, "", parentRef, gen)
	}
	if rulesetID, ok := entry["ruleset_id"].(string); ok && rulesetID != "" {
		appendVTProperty(exec, constants.TypeRule, "Ruleset ID: "+rulesetID, "", parentRef, gen)
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

func formatNetworkEndpoint(prefix, ip, port string) []string {
	if ip == "" && port == "" {
		return nil
	}
	if ip != "" && port != "" {
		return []string{prefix + ": " + ip + ":" + port}
	}
	if ip != "" {
		return []string{prefix + ": " + ip}
	}
	return []string{prefix + "Port: " + port}
}

func getNetworkContextString(values map[string]any, keys ...string) string {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if v, ok := values[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
			if s := fmt.Sprintf("%v", v); s != "" && s != "0" {
				return s
			}
		}
	}
	return ""
}

func formatNetworkContext(values map[string]any) string {
	var parts []string
	if e := getNetworkContextString(values, "EventID", ""); e != "" {
		parts = append(parts, "Event: "+e)
	}
	if e := getNetworkContextString(values, "Image", ""); e != "" {
		parts = append(parts, "Image: "+e)
	}
	if e := getNetworkContextString(values, "CommandLine", ""); e != "" {
		parts = append(parts, "Cmd: "+e)
	}
	if e := getNetworkContextString(values, "protocol", "Protocol"); e != "" {
		parts = append(parts, "Proto: "+strings.ToUpper(e))
	}

	srcParts := formatNetworkEndpoint("Src", getNetworkContextString(values, "src"+"_ip", "Source"+"Ip"), getNetworkContextString(values, "src"+"_port", "Source"+"Port"))
	parts = append(parts, srcParts...)

	dstParts := formatNetworkEndpoint("Dst", getNetworkContextString(values, "dest"+"_ip", "Destination"+"Ip"), getNetworkContextString(values, "dest"+"_port", "Destination"+"Port"))
	parts = append(parts, dstParts...)

	if e := getNetworkContextString(values, constants.TypeHostname, "Hostname"); e != "" {
		parts = append(parts, "Host: "+e)
	}
	if e := getNetworkContextString(values, "url", "Url"); e != "" {
		parts = append(parts, "URL: "+e)
	}

	knownKeys := []string{
		"EventID", "Image", "CommandLine", "protocol", "Protocol",
		"src_ip", "SourceIp", "src_port", "SourcePort",
		"dest_ip", "DestinationIp", "dest_port", "DestinationPort",
		constants.TypeHostname, "Hostname", "url", "Url",
		"SourceIsIpv6", "DestinationIsIpv6", "Initiated",
	}

	var extra []string
	for k, v := range values {
		if !slices.Contains(knownKeys, k) {
			if s := fmt.Sprintf("%v", v); s != "" && s != "0" && s != "<nil>" {
				extra = append(extra, fmt.Sprintf("%s: %s", formatIDSUnknownKey(k), s))
			}
		}
	}

	if len(extra) > 0 {
		sort.Strings(extra)
		parts = append(parts, extra...)
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
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

		if formatted := formatNetworkContext(values); formatted != "" {
			appendVTProperty(exec, constants.TypeMatchContext, formatted, "", parentRef, gen)
		}
	}
}

func appendFileIDSAlerts(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	results, ok := attr[vtKeyIDSResults].([]any)
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
	if ruleID, ok := entry["rule_id"].(string); ok && ruleID != "" {
		parts = append(parts, "ID: "+ruleID)
	}
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

	extractIDSAlertProperties(exec, entry, parentRef, gen)
	extractIDSAlertContext(exec, entry, parentRef, gen)
}

func extractIDSAlertProperties(exec *schema.ModuleExecution, entry map[string]any, parentRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if rawRule, ok := entry["rule_raw"].(string); ok && rawRule != "" {
		appendVTProperty(exec, constants.TypeRawRule, rawRule, "", parentRef, gen)
	}
	if src, ok := entry["rule_source"].(string); ok && src != "" {
		appendVTProperty(exec, constants.TypeSource, src, "", parentRef, gen)
	}
	if ruleURL, ok := entry["rule_url"].(string); ok && ruleURL != "" {
		appendVTProperty(exec, constants.TypeRule, ruleURL, "", parentRef, gen)
	}
	if category, ok := entry["rule_category"].(string); ok && category != "" {
		appendVTProperty(exec, constants.TypeCategory, category, "Rule Category", parentRef, gen)
	}
	if refs, ok := entry["rule_references"].([]any); ok {
		for _, r := range refs {
			if refStr, ok := r.(string); ok && refStr != "" {
				appendVTProperty(exec, constants.TypeReference, refStr, "", parentRef, gen)
			}
		}
	}
}

func formatIDSUnknownKey(k string) string {
	words := strings.Split(k, "_")
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, "")
}

func extractIDSAlertContext(exec *schema.ModuleExecution, entry map[string]any, parentRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	contexts, ok := entry["alert_context"].([]any)
	if !ok {
		return
	}

	for _, contextEntry := range contexts {
		ctx, ok := contextEntry.(map[string]any)
		if !ok {
			continue
		}

		if formatted := formatNetworkContext(ctx); formatted != "" {
			appendVTProperty(exec, constants.TypeMatchContext, formatted, "Alert Context", parentRef, gen)
		}
	}
}

func extractIDSStatsParts(attr map[string]any, parts *[]string) {
	stats, ok := attr["crowdsourced_ids_stats"].(map[string]any)
	if !ok {
		return
	}

	var statsParts []string
	levels := []struct {
		key   string
		label string
	}{
		{"high", "High"},
		{"medium", "Medium"},
		{"low", "Low"},
		{"info", "Info"},
	}
	for _, lvl := range levels {
		if count, ok := stats[lvl.key].(float64); ok && count > 0 {
			statsParts = append(statsParts, fmt.Sprintf("%s: %d", lvl.label, int(count)))
		}
	}
	if len(statsParts) > 0 {
		*parts = append(*parts, "IDS Stats: "+strings.Join(statsParts, ", "))
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
