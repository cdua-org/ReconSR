package virustotal

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *module) processCommunicatingFiles(ctx context.Context, funcName, urlPath string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if m.apiKey == demoIndicator {
		m.processCommunicatingFilesDemo(ctx, funcName, exec, gen)
		return
	}
	reqURL := fmt.Sprintf("%s/%s?limit=40", baseURL, urlPath)
	dbg.Printf("%s phase=communicating_files url=%q", funcName, reqURL)

	m.processPaginated(ctx, reqURL, exec, gen, func(item map[string]any) {
		extractCommunicatingFile(item, exec, gen)
	})

	dbg.Printf("%s success results=%d", funcName, len(exec.Results))
}

func extractCommunicatingFile(item map[string]any, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	sha256, ok := item["id"].(string)
	if !ok || sha256 == "" {
		return
	}

	attr, ok := item[constants.KeyAttributes].(map[string]any)
	if !ok {
		return
	}

	hashRef := &schema.EntityRef{
		Type:  constants.TypeFileHash,
		Value: "sha256:" + sha256,
	}

	primaryID := gen.NextID()
	hashRef.LocalID = primaryID

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeFileHash,
		Category: constants.CategoryProperty,
		Value:    "sha256:" + sha256,
		LocalID:  primaryID,
	})

	appendFileHashes(exec, attr, hashRef, gen)
	appendFileName(exec, attr, hashRef, gen)
	appendFileInfo(exec, attr, hashRef, gen)
	appendFileMagic(exec, attr, hashRef, gen)
	appendFileDates(exec, attr, hashRef, gen)
	appendFileThreatScore(exec, attr, hashRef, gen)
	appendFileThreatClassification(exec, attr, hashRef, gen)
	appendFileCategories(exec, attr, hashRef, gen)
	appendFileYaraRules(exec, attr, hashRef, gen)
	appendFileSigmaRules(exec, attr, hashRef, gen)
	appendFileIDSAlerts(exec, attr, hashRef, gen)
	appendFileMalwareConfig(exec, attr, hashRef, gen)
	appendFileTags(exec, attr, hashRef, gen)
	appendFileSandboxVerdicts(exec, attr, hashRef, gen)
	appendFileReputation(exec, attr, hashRef, gen)
	appendFileCertificates(exec, attr, hashRef, gen)
}

func appendFileHashes(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	hashFields := []struct {
		key    string
		prefix string
	}{
		{constants.KeyMD5, constants.KeyMD5},
		{constants.KeySHA1, constants.KeySHA1},
		{"ssdeep", "ssdeep"},
		{"vhash", "vhash"},
		{"authentihash", "authentihash"},
		{"tlsh", "tlsh"},
		{"permhash", "permhash"},
	}
	for _, h := range hashFields {
		if val, ok := attr[h.key].(string); ok && val != "" {
			appendVTProperty(exec, constants.TypeFileHash, h.prefix+":"+val, "", hashRef, gen)
		}
	}

	if peInfo, ok := attr["pe_info"].(map[string]any); ok {
		if imphash, ok := peInfo["imphash"].(string); ok && imphash != "" {
			appendVTProperty(exec, constants.TypeFileHash, "imphash:"+imphash, "", hashRef, gen)
		}
	}
}

func appendFileName(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	uniqueNames := make(map[string]bool)

	if name, ok := attr["meaningful_name"].(string); ok && name != "" {
		uniqueNames[name] = true
	}
	if names, ok := attr["names"].([]any); ok {
		for _, n := range names {
			if strName, ok := n.(string); ok && strName != "" {
				uniqueNames[strName] = true
			}
		}
	}

	for nameStr := range uniqueNames {
		if unescaped, err := url.QueryUnescape(nameStr); err == nil {
			nameStr = unescaped
		}
		appendVTProperty(exec, constants.TypeFileName, nameStr, "", hashRef, gen)
	}
}

func extractFileInfoParts(attr map[string]any) []string {
	var parts []string
	if typeDesc, ok := attr["type_description"].(string); ok && typeDesc != "" {
		parts = append(parts, "Type: "+typeDesc)
	}
	if sizeVal, ok := attr["size"].(float64); ok {
		parts = append(parts, fmt.Sprintf("Size: %d bytes", int64(sizeVal)))
	}
	if typeTags, ok := attr["type_tags"].([]any); ok {
		tags := make([]string, 0, len(typeTags))
		for _, t := range typeTags {
			if s, ok := t.(string); ok && s != "" {
				tags = append(tags, s)
			}
		}
		if len(tags) > 0 {
			parts = append(parts, "Tags: "+strings.Join(tags, ", "))
		}
	}
	return parts
}

func extractFileMetaParts(attr map[string]any) []string {
	var parts []string
	if sigInfo, ok := attr["signature_info"].(map[string]any); ok {
		extractSignatureMetaParts(sigInfo, &parts)
	}
	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardMetaParts(androguard, &parts)
	}
	if pdfInfo, ok := attr["pdf_info"].(map[string]any); ok {
		extractPDFInfoParts(pdfInfo, &parts)
	}
	return parts
}

func extractPDFInfoParts(pdfInfo map[string]any, parts *[]string) {
	fields := []struct {
		key   string
		label string
	}{
		{"javascript", "JavaScript"},
		{"flash", "Flash"},
		{"acroform", "AcroForm"},
		{"autoaction", "AutoAction"},
		{"openaction", "OpenAction"},
		{"encrypted", "Encrypted"},
		{"embedded_file", "EmbeddedFiles"},
	}
	var extracted []string
	if header, ok := pdfInfo["header"].(string); ok && header != "" {
		extracted = append(extracted, "Header: "+header)
	}
	for _, f := range fields {
		if val, ok := pdfInfo[f.key].(float64); ok && val > 0 {
			extracted = append(extracted, fmt.Sprintf("%s: %d", f.label, int(val)))
		}
	}
	if len(extracted) > 0 {
		*parts = append(*parts, "PDF Info: "+strings.Join(extracted, ", "))
	}
}

func extractSignatureMetaParts(sigInfo map[string]any, parts *[]string) {
	if origName, ok := sigInfo["original name"].(string); ok && origName != "" {
		*parts = append(*parts, "Original Name: "+origName)
	}
	if product, ok := sigInfo["product"].(string); ok && product != "" {
		*parts = append(*parts, "Product: "+product)
	}
	if copyright, ok := sigInfo["copyright"].(string); ok && copyright != "" {
		*parts = append(*parts, "Copyright: "+copyright)
	}
}

func extractAndroguardMetaParts(androguard map[string]any, parts *[]string) {
	if pkg, ok := androguard["Package"].(string); ok && pkg != "" {
		ver := ""
		if vName, ok := androguard["AndroidVersionName"].(string); ok && vName != "" {
			ver = " (v" + vName + ")"
		}
		*parts = append(*parts, "Android Package: "+pkg+ver)
	}
	if mainActivity, ok := androguard["main_activity"].(string); ok && mainActivity != "" {
		*parts = append(*parts, "Main Activity: "+mainActivity)
	}
	if minSDK, ok := androguard["MinSdkVersion"].(string); ok && minSDK != "" {
		*parts = append(*parts, "Min SDK: "+minSDK)
	}
	if targetSDK, ok := androguard["TargetSdkVersion"].(string); ok && targetSDK != "" {
		*parts = append(*parts, "Target SDK: "+targetSDK)
	}
}

func extractFileAnalyzerParts(attr map[string]any) []string {
	var parts []string

	extractFileAnalyzerVotes(attr, &parts)

	if packers, ok := attr["packers"].(map[string]any); ok {
		pList := make([]string, 0, len(packers))
		for k := range packers {
			pList = append(pList, k)
		}
		if len(pList) > 0 {
			parts = append(parts, "Packers: "+strings.Join(pList, ", "))
		}
	}
	if magika, ok := attr["magika"].(string); ok && magika != "" {
		parts = append(parts, "Magika: "+magika)
	}
	if detectiteasy, ok := attr["detectiteasy"].(map[string]any); ok {
		if filetype, ok := detectiteasy["filetype"].(string); ok && filetype != "" {
			parts = append(parts, "DetectItEasy: "+filetype)
		}
	}
	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardAnalyzerParts(androguard, &parts)
	}
	return parts
}

func extractFileAnalyzerVotes(attr map[string]any, parts *[]string) {
	if times, ok := attr["times_submitted"].(float64); ok && times > 0 {
		*parts = append(*parts, fmt.Sprintf("Times Submitted: %d", int(times)))
	}
	if sources, ok := attr["unique_sources"].(float64); ok && sources > 0 {
		*parts = append(*parts, fmt.Sprintf("Unique Sources: %d", int(sources)))
	}
	if votes, ok := attr["total_votes"].(map[string]any); ok {
		var voteParts []string
		if harmless, ok := votes["harmless"].(float64); ok && harmless > 0 {
			voteParts = append(voteParts, fmt.Sprintf("Harmless: %d", int(harmless)))
		}
		if malicious, ok := votes["malicious"].(float64); ok && malicious > 0 {
			voteParts = append(voteParts, fmt.Sprintf("Malicious: %d", int(malicious)))
		}
		if len(voteParts) > 0 {
			*parts = append(*parts, "Community Votes: "+strings.Join(voteParts, ", "))
		}
	}
}

func extractAndroguardAnalyzerParts(androguard map[string]any, parts *[]string) {
	if permDetails, ok := androguard["permission_details"].(map[string]any); ok {
		extractDangerousPerms(permDetails, parts)
	}
}

func extractDangerousPerms(permDetails map[string]any, parts *[]string) {
	var dangerousPerms []string
	for permName, rawDetails := range permDetails {
		isDangerous := false
		if details, ok := rawDetails.(map[string]any); ok {
			if permType, ok := details["permission_type"].(string); ok && strings.Contains(strings.ToLower(permType), "dangerous") {
				isDangerous = true
			}
		} else if strVal, ok := rawDetails.(string); ok && strings.Contains(strings.ToLower(strVal), "dangerous") {
			isDangerous = true
		}
		if isDangerous {
			shortName := strings.TrimPrefix(permName, "android.permission.")
			dangerousPerms = append(dangerousPerms, shortName)
		}
	}
	if len(dangerousPerms) > 0 {
		sort.Strings(dangerousPerms)
		*parts = append(*parts, "Dangerous Permissions: "+strings.Join(dangerousPerms, ", "))
	}
}

func appendFileInfo(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if parts := extractFileInfoParts(attr); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileInfo, strings.Join(parts, " | "), "", hashRef, gen)
	}
	if parts := extractFileMetaParts(attr); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileMeta, strings.Join(parts, " | "), "", hashRef, gen)
	}
	if parts := extractFileAnalyzerParts(attr); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileAnalyzer, strings.Join(parts, " | "), "", hashRef, gen)
	}
}

func appendFileDates(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	dateFields := []struct {
		key    string
		prefix string
	}{
		{"first_submission_date", "First Submission"},
		{"last_submission_date", "Last Submission"},
		{"last_analysis_date", "Last Analysis"},
		{"last_modification_date", "Last Modification"},
		{"creation_date", "Creation Date"},
	}

	for _, f := range dateFields {
		if tsVal, ok := attr[f.key].(float64); ok && tsVal > 0 {
			formatted := time.Unix(int64(tsVal), 0).UTC().Format(time.DateTime)
			appendVTProperty(exec, constants.TypeDate, f.prefix+": "+formatted, "", hashRef, gen)
		}
	}
}

func appendFileMagic(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if magic, ok := attr["magic"].(string); ok && magic != "" {
		appendVTProperty(exec, constants.TypeFileMagic, magic, "", hashRef, gen)
	}
}

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

func appendFileCertificates(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if sigInfo, ok := attr["signature_info"].(map[string]any); ok {
		extractX509Certificates(exec, sigInfo, hashRef, gen)
	}

	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardCertificates(exec, androguard, hashRef, gen)
	}
}

func extractAndroguardCertificates(exec *schema.ModuleExecution, androguard map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	cert, ok := androguard["certificate"].(map[string]any)
	if !ok {
		return
	}
	tp, ok := cert["thumbprint"].(string)
	if !ok || tp == "" {
		return
	}

	tpVal := "sha1:" + tp
	tpID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCertFingerprint,
		Category: constants.CategoryProperty,
		Value:    tpVal,
		Context:  "Android APK Certificate",
		Source:   hashRef,
		LocalID:  tpID,
	})
	tpRef := &schema.EntityRef{Type: constants.TypeCertFingerprint, Value: tpVal, LocalID: tpID}

	if issuerMap, ok := cert["Issuer"].(map[string]any); ok {
		if dn, ok := issuerMap["DN"].(string); ok && dn != "" {
			appendVTProperty(exec, constants.TypeCertIssuer, dn, "Android APK Certificate", tpRef, gen)
		}
	}

	if validTo, ok := cert["validto"].(string); ok && validTo != "" {
		t, err := time.Parse("2006-01-02 15:04:05", validTo)
		if err == nil {
			appendVTProperty(exec, constants.TypeCertNotAfter, t.UTC().Format(time.RFC3339), "Android APK Certificate", tpRef, gen)
		} else {
			appendVTProperty(exec, constants.TypeCertNotAfter, validTo, "Android APK Certificate", tpRef, gen)
		}
	}
}

func extractX509Certificates(exec *schema.ModuleExecution, sigInfo map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	x509List, ok := sigInfo["x509"].([]any)
	if !ok {
		return
	}
	for _, item := range x509List {
		cert, ok := item.(map[string]any)
		if !ok {
			continue
		}

		tp, ok := cert["thumbprint"].(string)
		if !ok || tp == "" {
			continue
		}

		tpVal := "sha1:" + tp
		tpID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCertFingerprint,
			Category: constants.CategoryProperty,
			Value:    tpVal,
			Context:  "Digital Signature",
			Source:   hashRef,
			LocalID:  tpID,
		})
		tpRef := &schema.EntityRef{Type: constants.TypeCertFingerprint, Value: tpVal, LocalID: tpID}

		if issuer, ok := cert["cert issuer"].(string); ok && issuer != "" {
			appendVTProperty(exec, constants.TypeCertIssuer, issuer, "Digital Signature", tpRef, gen)
		}
		if tp256, ok := cert["thumbprint_sha256"].(string); ok && tp256 != "" {
			appendVTProperty(exec, constants.TypeCertFingerprint, "sha256:"+tp256, "Digital Signature", tpRef, gen)
		}
		if validTo, ok := cert["valid to"].(string); ok && validTo != "" {
			t, err := time.Parse("2006-01-02 15:04:05", validTo)
			if err == nil {
				appendVTProperty(exec, constants.TypeCertNotAfter, t.UTC().Format(time.RFC3339), "Digital Signature", tpRef, gen)
			} else {
				appendVTProperty(exec, constants.TypeCertNotAfter, validTo, "Digital Signature", tpRef, gen)
			}
		}
	}
}
