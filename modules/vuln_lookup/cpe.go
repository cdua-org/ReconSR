package vuln_lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func (m *module) searchCirclCPE(ctx context.Context, targetType, targetValue string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncSearchCirclCPE)

	switch targetType {
	case constants.TypeCPE, constants.TypeCPE23:
		if !isValidSpecificCPE(targetValue) {
			dlog.Printf("%s stage=drop_invalid target=%q reason=\"no specific version\"", constants.FuncSearchCirclCPE, targetValue)
			return exec
		}

		if _, ok := m.cpeCache.Load(targetValue); ok {
			dlog.Printf("%s stage=cache_hit target=%q", constants.FuncSearchCirclCPE, targetValue)
			return exec
		}
		m.cpeCache.Store(targetValue, true)

		if m.apiKey == demoIndicator {
			m.searchCirclCPEDemo(ctx, &exec, targetValue, gen)
			return exec
		}
		m.fetchAndParseCPE(ctx, &exec, targetValue, gen)
	default:
		modutil.SetError(&exec, "unsupported target type: %v", fmt.Errorf("%s", targetType))
	}

	return exec
}

func (m *module) fetchAndParseCPE(ctx context.Context, exec *schema.ModuleExecution, cpeStr string, gen *modutil.LocalIDGenerator) {
	baseURL := circlAPIBaseURL + "/api/vulnerability/cpesearch/" + url.PathEscape(cpeStr)

	maxPages := max(1, resolver.CirclCPEMaxPages)
	perPage := max(1, resolver.CirclCPEPerPage)

	for page := 1; page <= maxPages; page++ {
		reqURL, err := buildCPEURL(baseURL, page, perPage)
		if err != nil {
			modutil.SetError(exec, "url parse error: %v", err)
			return
		}

		m.mu.Lock()
		raw, err := m.fetchCircl(ctx, reqURL.String(), constants.FuncSearchCirclCPE, cpeStr)
		m.mu.Unlock()

		if err != nil {
			dlog.Printf("%s error target=%q err=%v", constants.FuncSearchCirclCPE, cpeStr, err)
			modutil.SetError(exec, fmt.Sprintf("fetch error on page %d: %%v", page), err)
			modutil.SetRawFromBytes(exec, raw)
			break
		}
		if len(raw) == 0 {
			break
		}
		modutil.SetRawFromBytes(exec, raw)

		count := m.parseCPEResponse(exec, raw, cpeStr, gen)
		dlog.Printf("%s success target=%q results=%d", constants.FuncSearchCirclCPE, cpeStr, count)

		if count < perPage {
			break
		}

		if page < maxPages {
			time.Sleep(resolver.CirclRetryBaseDelay)
		}
	}
}

func (m *module) parseCPEResponse(exec *schema.ModuleExecution, raw []byte, targetCPE string, gen *modutil.LocalIDGenerator) int {
	var resp CIRCLCPEListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		dlog.Printf("%s error stage=parse_cpe_response err=%v", constants.FuncSearchCirclCPE, err)
		return 0
	}

	var combinedList []CIRCLCVEResponse
	if len(resp.CVEListV5) > 0 {
		combinedList = append(combinedList, resp.CVEListV5...)
	}
	if len(resp.NVDList) > 0 {
		combinedList = append(combinedList, resp.NVDList...)
	}

	parts := strings.Split(targetCPE, ":")
	targetProduct := ""
	targetVersion := ""
	if len(parts) >= 6 {
		targetProduct = strings.ToLower(parts[4])
		targetVersion = parts[5]
	}

	for i := range combinedList {
		cveResp := &combinedList[i]
		if !isCveApplicable(targetProduct, targetVersion, cveResp) {
			continue
		}

		cveID := cveResp.CVEMetadata.CVEId
		if cveID == "" {
			continue
		}

		cveLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVE,
			Category: constants.CategoryProperty,
			Value:    cveID,
			LocalID:  cveLocalID,
		})

		m.cveCache.Store(cveID, true)

		cveSource := &schema.EntityRef{
			Type:    constants.TypeCVE,
			Value:   cveID,
			LocalID: cveLocalID,
		}

		m.extractCVEResults(exec, cveResp, cveSource, gen)
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCPE,
		Category: constants.CategoryProperty,
		Value:    targetCPE,
		LocalID:  gen.NextID(),
		Applied:  true,
	})

	return len(combinedList)
}

func isValidSpecificCPE(cpe string) bool {
	if !strings.HasPrefix(cpe, "cpe:") {
		return false
	}

	parts := strings.Split(cpe, ":")
	var versionIdx int

	if strings.HasPrefix(cpe, "cpe:2.3:") {
		versionIdx = 5
	} else {
		versionIdx = 4
	}

	if len(parts) <= versionIdx {
		return false
	}

	version := parts[versionIdx]
	if version == "" || version == "*" || version == "-" {
		return false
	}

	return true
}

func buildCPEURL(baseURL string, page, perPage int) (*url.URL, error) {
	reqURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("url.Parse: %w", err)
	}

	q := reqURL.Query()
	if resolver.CirclCPESortOrder != "" {
		q.Set("sort_order", resolver.CirclCPESortOrder)
	}
	if resolver.CirclCPEDateSort != "" {
		q.Set("date_sort", resolver.CirclCPEDateSort)
	}
	q.Set("per_page", strconv.Itoa(perPage))
	q.Set("page", strconv.Itoa(page))
	if resolver.CirclCPESource != "" {
		q.Set("source", resolver.CirclCPESource)
	}
	reqURL.RawQuery = q.Encode()
	return reqURL, nil
}

func compareVersions(v1, v2 string) int {
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	maxLength := max(len(parts1), len(parts2))

	for i := range maxLength {
		p1, p2 := 0, 0
		if i < len(parts1) {
			p1 = extractLeadingInt(parts1[i])
		}
		if i < len(parts2) {
			p2 = extractLeadingInt(parts2[i])
		}
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

func extractLeadingInt(s string) int {
	var digits strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits.WriteRune(c)
		} else {
			break
		}
	}
	if digits.Len() == 0 {
		return 0
	}
	val, err := strconv.Atoi(digits.String())
	if err != nil {
		return 0
	}
	return val
}

func isCveApplicable(targetProduct, targetVersion string, cve *CIRCLCVEResponse) bool {
	if targetVersion == "" || targetVersion == "*" || targetVersion == "-" {
		return true
	}

	foundMatchingProductBlock := false
	foundValidVersionBlockForProduct := false

	for i := range cve.Containers.CNA.Affected {
		affected := &cve.Containers.CNA.Affected[i]
		product := strings.ToLower(affected.Product)

		normalizedTargetProduct := strings.ReplaceAll(targetProduct, "_", " ")
		normalizedProduct := strings.ReplaceAll(product, "_", " ")

		if !strings.Contains(normalizedProduct, normalizedTargetProduct) && !strings.Contains(normalizedProduct, targetProduct) && product != ValueNA && product != ValueUnknown {
			continue
		}

		foundMatchingProductBlock = true

		for j := range affected.Versions {
			v := &affected.Versions[j]
			if v.Version == ValueNA || v.Version == ValueUnknown {
				continue
			}
			foundValidVersionBlockForProduct = true

			if isVersionInRange(targetVersion, v) {
				status := evaluateStatus(targetVersion, v)
				if status == StatusAffected {
					return true
				}
			}
		}
	}

	if foundValidVersionBlockForProduct {
		return false
	}

	_ = foundMatchingProductBlock

	return false
}

func isVersionInRange(target string, v *Version) bool {
	start := normalizeStartBound(v.Version)

	if after, found := strings.CutPrefix(start, "<="); found {
		return compareVersions(target, strings.TrimSpace(after)) <= 0
	}
	if after, found := strings.CutPrefix(start, "<"); found {
		return compareVersions(target, strings.TrimSpace(after)) < 0
	}

	if start != "" && compareVersions(target, start) < 0 {
		return false
	}

	if exceedsUpperBounds(target, v) {
		return false
	}

	if start != "" && start != target && v.LessThan == "" && v.LessThanOrEqual == "" {
		return parseLegacyVersionString(target, v.Version)
	}

	return true
}

func normalizeStartBound(start string) string {
	if start == "0" || start == "unspecified" || start == "any" || start == "*" {
		return ""
	}
	return start
}

func exceedsUpperBounds(target string, v *Version) bool {
	if v.LessThan != "" && compareVersions(target, v.LessThan) >= 0 {
		return true
	}
	if v.LessThanOrEqual != "" && compareVersions(target, v.LessThanOrEqual) > 0 {
		return true
	}
	return false
}

func evaluateStatus(target string, v *Version) string {
	currentStatus := v.Status
	if currentStatus == "" {
		currentStatus = StatusAffected
	}

	for i := range v.Changes {
		change := &v.Changes[i]
		if compareVersions(target, change.At) >= 0 {
			currentStatus = change.Status
		}
	}
	return currentStatus
}

var legacyBoundRe = regexp.MustCompile(`(?i)(?:through|before|up to(?:\s+including)?|<=|<)\s*([0-9]+(?:\.[0-9]+)*)`)

func parseLegacyVersionString(target, text string) bool {
	if target != "" && strings.Contains(text, target) {
		return true
	}

	matches := legacyBoundRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return false
	}

	for _, match := range matches {
		bound := match[1]
		operator := strings.TrimSpace(strings.Split(match[0], bound)[0])
		operator = strings.ToLower(operator)

		var isLess bool
		if strings.Contains(operator, "before") || (strings.Contains(operator, "<") && !strings.Contains(operator, "=")) {
			isLess = compareVersions(target, bound) < 0
		} else {
			isLess = compareVersions(target, bound) <= 0
		}

		if isLess {
			return true
		}
	}
	return false
}
