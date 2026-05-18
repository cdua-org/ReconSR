package vuln_lookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func getCirclVuln(ctx context.Context, targetType, targetValue string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetCirclVuln)

	switch targetType {
	case constants.TypeCVE:
		fetchAndParseCVE(ctx, &exec, targetValue)

	default:
		modutil.SetError(&exec, "unsupported target type: %v", fmt.Errorf("%s", targetType))
	}

	return exec
}

func fetchAndParseCVE(ctx context.Context, exec *schema.ModuleExecution, cve string) {
	apiURL := buildCVESearchURL(cve)
	raw, err := fetchCircl(ctx, apiURL)
	if err != nil {
		modutil.SetError(exec, "%v", err)
		modutil.SetRawFromBytes(exec, raw)
		return
	}
	if len(raw) == 0 {
		return
	}
	modutil.SetRawFromBytes(exec, raw)
	parseCVEResponse(exec, raw)
}

func parseCVEResponse(exec *schema.ModuleExecution, raw []byte) {
	var resp CIRCLCVEResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		dlog.Printf("%s error stage=parse_cve_response err=%v", constants.FuncGetCirclVuln, err)
		return
	}

	extractCVEResults(exec, &resp, nil)
}

func extractCVEResults(exec *schema.ModuleExecution, resp *CIRCLCVEResponse, source *schema.EntityRef) {
	for _, desc := range resp.Containers.CNA.Descriptions {
		if desc.Lang == "en" || desc.Lang == "en-US" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSummary,
				Category: constants.CategoryProperty,
				Value:    desc.Value,
				Source:   source,
			})
			break
		}
	}

	extractProblemTypes(exec, resp.Containers.CNA.ProblemTypes, source)
	extractMetrics(exec, resp.Containers.CNA.Metrics, source)
	extractCPEs(exec, resp.Containers.CNA.CpeApplicability, source)

	for _, adp := range resp.Containers.ADP {
		extractProblemTypes(exec, adp.ProblemTypes, source)
		extractMetrics(exec, adp.Metrics, source)
	}

	hasCNAMetrics := len(resp.Containers.CNA.Metrics) > 0
	hasCNACWE := hasCWEResults(resp.Containers.CNA.ProblemTypes)
	extractVulnLookupMeta(exec, resp.VulnLookupMeta, source, hasCNAMetrics, hasCNACWE)
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

func extractCPEs(exec *schema.ModuleExecution, applicability []CpeApplicability, source *schema.EntityRef) {
	seen := make(map[string]bool)
	for _, app := range applicability {
		for _, node := range app.Nodes {
			for _, match := range node.CpeMatch {
				if match.Criteria != "" && !seen[match.Criteria] {
					seen[match.Criteria] = true
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:   constants.TypeCPE,
						Value:  match.Criteria,
						Source: source,
					})
				}
			}
		}
	}
}

func extractProblemTypes(exec *schema.ModuleExecution, problemTypes []ProblemType, source *schema.EntityRef) {
	for _, pt := range problemTypes {
		for _, desc := range pt.Descriptions {
			if desc.CWEId != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeCWE,
					Category: constants.CategoryProperty,
					Value:    desc.CWEId,
					Context:  desc.Description,
					Source:   source,
				})
			}
		}
	}
}

func extractMetrics(exec *schema.ModuleExecution, metrics []Metric, source *schema.EntityRef) {
	for _, m := range metrics {
		if m.Other != nil {
			extractOtherMetric(exec, m.Other, source)
			continue
		}

		if m.CVSSV40 != nil {
			appendCVSS(exec, "CVSS 4.0", m.CVSSV40.BaseSeverity, m.CVSSV40.VectorString, m.CVSSV40.BaseScore, source)
			continue
		}
		if m.CVSSV31 != nil {
			appendCVSS(exec, "CVSS 3.1", m.CVSSV31.BaseSeverity, m.CVSSV31.VectorString, m.CVSSV31.BaseScore, source)
			continue
		}
		if m.CVSSV30 != nil {
			appendCVSS(exec, "CVSS 3.0", m.CVSSV30.BaseSeverity, m.CVSSV30.VectorString, m.CVSSV30.BaseScore, source)
		}
	}
}

func extractOtherMetric(exec *schema.ModuleExecution, other *OtherMetric, source *schema.EntityRef) {
	switch other.Type {
	case "ssvc":
		for _, opt := range other.Content.Options {
			if opt.Exploitation != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSSVC,
					Category: constants.CategoryProperty,
					Value:    "Exploitation: " + opt.Exploitation,
					Source:   source,
				})
			}
			if opt.Automatable != "" {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeSSVC,
					Category: constants.CategoryProperty,
					Value:    "Automatable: " + opt.Automatable,
					Source:   source,
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
			})
		}
	}
}

func appendCVSS(exec *schema.ModuleExecution, ctx, severity, vector string, score float64, source *schema.EntityRef) {
	val := fmt.Sprintf("%s / %s / %.1f", severity, vector, score)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCVSS,
		Category: constants.CategoryProperty,
		Value:    val,
		Context:  ctx,
		Source:   source,
	})
}

func extractVulnLookupMeta(exec *schema.ModuleExecution, meta *VulnLookupMeta, source *schema.EntityRef, hasCNAMetrics, hasCNACWE bool) {
	if meta == nil {
		return
	}

	extractEPSS(exec, meta.EPSS, source)

	if meta.NVD == "" {
		return
	}

	var nvd NVDWrapper
	if err := json.Unmarshal([]byte(meta.NVD), &nvd); err != nil {
		dlog.Printf("%s error stage=parse_nvd_meta err=%v", constants.FuncGetCirclVuln, err)
		return
	}

	if !hasCNAMetrics {
		extractNVDMetrics(exec, &nvd.CVE.Metrics, source)
	}
	if !hasCNACWE {
		extractNVDWeaknesses(exec, nvd.CVE.Weaknesses, source)
	}
}

func extractEPSS(exec *schema.ModuleExecution, epss *EPSSData, source *schema.EntityRef) {
	if epss == nil {
		return
	}
	if epss.EPSS != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeEPSS,
			Category: constants.CategoryProperty,
			Value:    formatAsPercentage(epss.EPSS),
			Source:   source,
		})
	}
	if epss.Percentile != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeRankEPSS,
			Category: constants.CategoryProperty,
			Value:    formatAsPercentage(epss.Percentile),
			Source:   source,
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

func extractNVDMetrics(exec *schema.ModuleExecution, metrics *NVDMetrics, source *schema.EntityRef) {
	if extractNVDCVSSEntries(exec, metrics.CVSSV40, "CVSS 4.0", source) {
		return
	}
	if extractNVDCVSSEntries(exec, metrics.CVSSV31, "CVSS 3.1", source) {
		return
	}
	if extractNVDCVSSEntries(exec, metrics.CVSSV30, "CVSS 3.0", source) {
		return
	}
	extractNVDCVSSV2(exec, metrics.CVSSV2, source)
}

func extractNVDCVSSEntries(exec *schema.ModuleExecution, entries []NVDCVSSEntry, ctx string, source *schema.EntityRef) bool {
	if len(entries) == 0 {
		return false
	}
	d := entries[0].CVSSData
	appendCVSS(exec, ctx, d.BaseSeverity, d.VectorString, d.BaseScore, source)
	return true
}

func extractNVDCVSSV2(exec *schema.ModuleExecution, entries []NVDCVSSEntryV2, source *schema.EntityRef) {
	if len(entries) == 0 {
		return
	}
	e := entries[0]
	severity := e.BaseSeverity
	if severity == "" {
		severity = e.CVSSData.BaseSeverity
	}
	appendCVSS(exec, "CVSS 2.0", severity, e.CVSSData.VectorString, e.CVSSData.BaseScore, source)
}

func extractNVDWeaknesses(exec *schema.ModuleExecution, weaknesses []NVDWeakness, source *schema.EntityRef) {
	for _, w := range weaknesses {
		for _, desc := range w.Description {
			if isValidCWE(desc.Value) {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeCWE,
					Category: constants.CategoryProperty,
					Value:    desc.Value,
					Source:   source,
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

func fetchCircl(ctx context.Context, apiURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}

	dlog.Printf("%s stage=request_start url=%q", constants.FuncGetCirclVuln, apiURL)

	var body []byte
	var lastErr error
	for attempt := range resolver.MaxRetriesCircl {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("do request: %w", err)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dlog.Printf("%s body_close_failed url=%q err=%v", constants.FuncGetCirclVuln, apiURL, cerr)
		}
		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		action := httputil.ClassifyStatus(resp.StatusCode)
		if action == httputil.Abort {
			if resp.StatusCode == http.StatusNotFound {
				dlog.Printf("%s not_found url=%q status=%d", constants.FuncGetCirclVuln, apiURL, resp.StatusCode)
				return nil, nil
			}
			return body, fmt.Errorf("http %d", resp.StatusCode)
		}
		if action == httputil.RateLimit {
			dlog.Printf("%s rate_limited url=%q attempt=%d", constants.FuncGetCirclVuln, apiURL, attempt)
			if !httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt, resolver.RetryBaseDelay)) {
				return body, fmt.Errorf("context canceled: %w", ctx.Err())
			}
			lastErr = errors.New("http 429")
			continue
		}
		if action == httputil.Retry {
			dlog.Printf("%s retry_status=%d url=%q attempt=%d", constants.FuncGetCirclVuln, resp.StatusCode, apiURL, attempt)
			if !httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt, resolver.RetryBaseDelay)) {
				return body, fmt.Errorf("context canceled: %w", ctx.Err())
			}
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
	}

	return body, lastErr
}

var circlAPIBaseURL = "https://vulnerability.circl.lu"

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
