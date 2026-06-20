package virustotal

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func appendVTProperty(exec *schema.ModuleExecution, resultType, value, resultContext string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    trimmedValue,
		Context:  strings.TrimSpace(resultContext),
		Source:   source,
		LocalID:  gen.NextID(),
	})
}

func extractVTTags(attr map[string]any) []string {
	rawTags, ok := attr["tags"].([]any)
	if !ok || len(rawTags) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(rawTags))
	tags := make([]string, 0, len(rawTags))
	for _, rawTag := range rawTags {
		tag, ok := rawTag.(string)
		if !ok {
			continue
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}

	sort.Strings(tags)
	return tags
}

func (m *module) extractThreatScore(attr map[string]any, entityType, entityValue string, src *schema.EntityRef, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
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

	var tag string
	if malicious > 0 {
		tag = constants.TagMalicious
	} else if suspicious > 0 {
		tag = constants.TagSuspicious
	}

	if tag != "" && entityType != "" && entityValue != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:    entityType,
			Value:   entityValue,
			Tags:    []string{tag},
			LocalID: gen.NextID(),
		})
	}

	engines := extractEngines(attr)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeThreatScore,
		Category: constants.CategoryProperty,
		Value:    fmt.Sprintf("Malicious: %d, Suspicious: %d", malicious, suspicious),
		Context:  engines,
		Source:   src,
		LocalID:  gen.NextID(),
	})
}

func extractEngines(attr map[string]any) string {
	var malicious, suspicious []string
	results, ok := attr["last_analysis_results"].(map[string]any)
	if !ok {
		return ""
	}

	for _, v := range results {
		res, ok := v.(map[string]any)
		if !ok {
			continue
		}
		cat, ok := res[constants.KeyCategory].(string)
		if !ok {
			continue
		}
		eng, ok := res["engine_name"].(string)
		if ok && eng != "" {
			switch cat {
			case constants.TagMalicious:
				malicious = append(malicious, eng)
			case constants.TagSuspicious:
				suspicious = append(suspicious, eng)
			}
		}
	}

	var parts []string
	if len(malicious) > 0 {
		sort.Strings(malicious)
		parts = append(parts, "Malicious: "+strings.Join(malicious, ", "))
	}
	if len(suspicious) > 0 {
		sort.Strings(suspicious)
		parts = append(parts, "Suspicious: "+strings.Join(suspicious, ", "))
	}

	return strings.Join(parts, "; ")
}

func normalizeVTText(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func formatVTInt(value any) (string, bool) {
	switch typedValue := value.(type) {
	case float64:
		return strconv.FormatInt(int64(typedValue), 10), true
	case int:
		return strconv.Itoa(typedValue), true
	case int64:
		return strconv.FormatInt(typedValue, 10), true
	case json.Number:
		return typedValue.String(), true
	default:
		return "", false
	}
}
