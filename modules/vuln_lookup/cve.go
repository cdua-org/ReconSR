package vuln_lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dateutil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func (m *module) enrichCirclCVE(ctx context.Context, targetType, targetValue string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncEnrichCirclCVE)

	switch targetType {
	case constants.TypeCVE:
		if _, ok := m.cveCache.Load(targetValue); ok {
			dlog.Printf("%s stage=cache_hit target=%q", constants.FuncEnrichCirclCVE, targetValue)
			return exec
		}
		m.cveCache.Store(targetValue, true)

		if m.apiKey == demoIndicator {
			m.enrichCirclCVEDemo(ctx, &exec, targetValue, gen)
			return exec
		}
		m.fetchAndParseCVE(ctx, &exec, targetValue, gen)

	default:
		modutil.SetError(&exec, "unsupported target type: %v", fmt.Errorf("%s", targetType))
	}

	return exec
}

func (m *module) fetchAndParseCVE(ctx context.Context, exec *schema.ModuleExecution, cve string, gen *modutil.LocalIDGenerator) {
	apiURL := buildCVESearchURL(cve)

	m.mu.Lock()
	raw, err := m.fetchCircl(ctx, apiURL, constants.FuncEnrichCirclCVE, cve)
	m.mu.Unlock()
	if err != nil {
		dlog.Printf("%s error target=%q err=%v", constants.FuncEnrichCirclCVE, cve, err)
		modutil.SetError(exec, "%v", err)
		modutil.SetRawFromBytes(exec, raw)
		return
	}
	if len(raw) == 0 {
		return
	}
	modutil.SetRawFromBytes(exec, raw)
	m.parseCVEResponse(exec, raw, cve, gen)
	dlog.Printf("%s success target=%q results=%d", constants.FuncEnrichCirclCVE, cve, len(exec.Results))
}

func (m *module) parseCVEResponse(exec *schema.ModuleExecution, raw []byte, targetCVE string, gen *modutil.LocalIDGenerator) {
	var resp CIRCLCVEResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		dlog.Printf("%s error stage=parse_cve_response err=%v", constants.FuncEnrichCirclCVE, err)
		return
	}

	m.extractCVEResults(exec, &resp, nil, gen)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:    constants.TypeCVE,
		Value:   targetCVE,
		LocalID: gen.NextID(),
		Applied: true,
	})
}

func (m *module) extractCVEResults(exec *schema.ModuleExecution, resp *CIRCLCVEResponse, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if resp.CVEMetadata.DatePublished != "" {
		published := resp.CVEMetadata.DatePublished
		if day, ok := dateutil.NormalizeDay(published); ok {
			published = day
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Published: " + published,
			Source:   source,
			LocalID:  gen.NextID(),
		})
	}

	if resp.Containers.CNA.Title != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDescription,
			Category: constants.CategoryProperty,
			Value:    strings.TrimSpace(resp.Containers.CNA.Title),
			Source:   source,
			LocalID:  gen.NextID(),
		})
	}

	for _, desc := range resp.Containers.CNA.Descriptions {
		if desc.Lang == "en" || desc.Lang == "en-US" {
			cleanValue := strings.Join(strings.Fields(desc.Value), " ")
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSummary,
				Category: constants.CategoryProperty,
				Value:    cleanValue,
				Source:   source,
				LocalID:  gen.NextID(),
			})
			break
		}
	}

	seenRefs := make(map[string]bool)
	for _, ref := range resp.Containers.CNA.References {
		if ref.URL == "" || seenRefs[ref.URL] {
			continue
		}
		isExploit := false
		for _, tag := range ref.Tags {
			if strings.Contains(strings.ToLower(tag), "exploit") {
				isExploit = true
				break
			}
		}
		if isExploit {
			seenRefs[ref.URL] = true
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeExploit,
				Category: constants.CategoryProperty,
				Value:    ref.URL,
				Source:   source,
				LocalID:  gen.NextID(),
			})
		}
	}

	extractProblemTypes(exec, resp.Containers.CNA.ProblemTypes, source, gen)
	extractMetrics(exec, resp.Containers.CNA.Metrics, source, gen)
	m.extractCPEs(exec, resp.Containers.CNA.CpeApplicability, source, gen)

	for _, adp := range resp.Containers.ADP {
		extractProblemTypes(exec, adp.ProblemTypes, source, gen)
		extractMetrics(exec, adp.Metrics, source, gen)
	}

	hasCNAMetrics := len(resp.Containers.CNA.Metrics) > 0
	hasCNACWE := hasCWEResults(resp.Containers.CNA.ProblemTypes)
	extractVulnLookupMeta(exec, resp.VulnLookupMeta, source, hasCNAMetrics, hasCNACWE, gen)
}

func hasCWEResults(problemTypes []ProblemType) bool {
	for _, pt := range problemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CWEId != "" {
				return true
			}
		}
	}
	return false
}

func (m *module) extractCPEs(exec *schema.ModuleExecution, applicability []CpeApplicability, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	seen := make(map[string]bool)
	for _, app := range applicability {
		for _, node := range app.Nodes {
			for _, match := range node.CpeMatch {
				if match.Criteria != "" && !seen[match.Criteria] {
					seen[match.Criteria] = true
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:     constants.TypeCPE,
						Category: constants.CategoryProperty,
						Value:    match.Criteria,
						Source:   source,
						LocalID:  gen.NextID(),
					})
					m.cpeCache.Store(match.Criteria, true)
				}
			}
		}
	}
}

func extractProblemTypes(exec *schema.ModuleExecution, problemTypes []ProblemType, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	seenCWEs := make(map[string]bool)
	for _, pt := range problemTypes {
		for _, desc := range pt.Descriptions {
			cweID := strings.ToUpper(desc.CWEId)
			if cweID == "" || seenCWEs[cweID] {
				continue
			}
			seenCWEs[cweID] = true

			cweLocalID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeCWE,
				Category: constants.CategoryProperty,
				Value:    cweID,
				Source:   source,
				LocalID:  cweLocalID,
			})

			ctxDesc := getCWEDescription(cweID)
			if ctxDesc != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeDescription,
					Category: constants.CategoryProperty,
					Value:    ctxDesc,
					Source: &schema.EntityRef{
						Type:    constants.TypeCWE,
						Value:   cweID,
						LocalID: cweLocalID,
					},
					LocalID: gen.NextID(),
				})
			}
		}
	}
}

func extractMetrics(exec *schema.ModuleExecution, metrics []Metric, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	var overallBestVersion float64
	var overallBestCVSS *UniversalCVSS

	for _, m := range metrics {
		if m.Other != nil {
			extractOtherMetric(exec, m.Other, source, gen)
			continue
		}

		if m.BestCVSS != nil && m.BestCVSSVersion > overallBestVersion {
			overallBestVersion = m.BestCVSSVersion
			overallBestCVSS = m.BestCVSS
		}
	}

	if overallBestCVSS != nil {
		ctx := fmt.Sprintf("CVSS %.1f", overallBestVersion)
		appendCVSS(exec, ctx, overallBestCVSS.BaseSeverity, overallBestCVSS.VectorString, overallBestCVSS.BaseScore, source, gen)
	}
}

func extractOtherMetric(exec *schema.ModuleExecution, other *OtherMetric, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	switch other.Type {
	case "ssvc":
		for _, opt := range other.Content.Options {
			if opt.Exploitation != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSSVC,
					Category: constants.CategoryProperty,
					Value:    "Exploitation: " + opt.Exploitation,
					Source:   source,
					LocalID:  gen.NextID(),
				})
			}
			if opt.Automatable != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSSVC,
					Category: constants.CategoryProperty,
					Value:    "Automatable: " + opt.Automatable,
					Source:   source,
					LocalID:  gen.NextID(),
				})
			}
		}
	case "kev":
		if other.Content.DateAdded != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeKEV,
				Category: constants.CategoryProperty,
				Value:    other.Content.DateAdded,
				Source:   source,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func appendCVSS(exec *schema.ModuleExecution, ctx, severity, vector string, score float64, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	val := fmt.Sprintf("%s / %s / %.1f", severity, vector, score)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCVSS,
		Category: constants.CategoryProperty,
		Value:    val,
		Context:  ctx,
		Source:   source,
		LocalID:  gen.NextID(),
	})
}

func extractVulnLookupMeta(exec *schema.ModuleExecution, meta *VulnLookupMeta, source *schema.EntityRef, hasCNAMetrics, hasCNACWE bool, gen *modutil.LocalIDGenerator) {
	if meta == nil {
		return
	}

	extractEPSS(exec, meta.EPSS, source, gen)

	if meta.NVD == "" {
		return
	}

	var nvd NVDWrapper
	if err := json.Unmarshal([]byte(meta.NVD), &nvd); err != nil {
		dlog.Printf("%s error stage=parse_nvd_meta err=%v", constants.FuncEnrichCirclCVE, err)
		return
	}

	if !hasCNAMetrics {
		extractNVDMetrics(exec, &nvd.CVE.Metrics, source, gen)
	}
	if !hasCNACWE {
		extractNVDWeaknesses(exec, nvd.CVE.Weaknesses, source, gen)
	}
}

func extractEPSS(exec *schema.ModuleExecution, epss *EPSSData, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if epss == nil {
		return
	}
	if epss.EPSS != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeEPSS,
			Category: constants.CategoryProperty,
			Value:    formatAsPercentage(epss.EPSS),
			Source:   source,
			LocalID:  gen.NextID(),
		})
	}
	if epss.Percentile != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeRankEPSS,
			Category: constants.CategoryProperty,
			Value:    formatAsPercentage(epss.Percentile),
			Source:   source,
			LocalID:  gen.NextID(),
		})
	}
}

func formatAsPercentage(val string) string {
	f, err := strconv.ParseFloat(val, 64)
	if err == nil {
		return fmt.Sprintf("%.2f%%", f*100)
	}
	return val
}

func extractNVDMetrics(exec *schema.ModuleExecution, metrics *NVDMetrics, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if metrics != nil && metrics.BestCVSS != nil {
		ctx := fmt.Sprintf("CVSS %.1f", metrics.BestCVSSVersion)
		appendCVSS(exec, ctx, metrics.BestCVSS.BaseSeverity, metrics.BestCVSS.VectorString, metrics.BestCVSS.BaseScore, source, gen)
	}
}

func extractNVDWeaknesses(exec *schema.ModuleExecution, weaknesses []NVDWeakness, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	seenCWEs := make(map[string]bool)
	for _, w := range weaknesses {
		for _, desc := range w.Description {
			cweID := strings.ToUpper(desc.Value)
			if !isValidCWE(cweID) || seenCWEs[cweID] {
				continue
			}
			seenCWEs[cweID] = true

			cweLocalID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeCWE,
				Category: constants.CategoryProperty,
				Value:    cweID,
				Source:   source,
				LocalID:  cweLocalID,
			})

			ctxDesc := getCWEDescription(cweID)
			if ctxDesc != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeDescription,
					Category: constants.CategoryProperty,
					Value:    ctxDesc,
					Source: &schema.EntityRef{
						Type:    constants.TypeCWE,
						Value:   cweID,
						LocalID: cweLocalID,
					},
					LocalID: gen.NextID(),
				})
			}
		}
	}
}

func isValidCWE(val string) bool {
	if !strings.HasPrefix(val, "CWE-") {
		return false
	}
	suffix := val[len("CWE-"):]
	if suffix == "" {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func buildCVESearchURL(cve string) string {
	u, err := url.Parse(circlAPIBaseURL + "/api/vulnerability/" + url.PathEscape(cve))
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("with_meta", strconv.FormatBool(resolver.CirclWithMeta))
	q.Set("with_linked", strconv.FormatBool(resolver.CirclWithLinked))
	q.Set("with_comments", strconv.FormatBool(resolver.CirclWithComments))
	q.Set("with_bundles", strconv.FormatBool(resolver.CirclWithBundles))
	q.Set("with_sightings", strconv.FormatBool(resolver.CirclWithSightings))
	u.RawQuery = q.Encode()
	return u.String()
}
