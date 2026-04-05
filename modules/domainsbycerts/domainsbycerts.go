// Package domainsbycerts provides functionality to discover subdomains
// for a given target domain by querying Certificate Transparency (CT) logs
// and passive DNS sources with built-in retries and fallbacks.
package domainsbycerts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

const (
	timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"
	timeFormatDate    = "2006-01-02 15:04:05"
)

// module represents the domainsbycerts module implementation.
type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

// Name provides the unique identifier used by the dispatcher for routing.
func (m *module) Name() string {
	return "domainsbycerts"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_domains"},
		InputTypes: []string{"domain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_domains" {
			execution = getDomains(data.Target.Value)
		} else {
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func getDomains(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_domains",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	allDomains := collectAllDomains(ctx, target)

	if len(allDomains.domains) == 0 {
		errMsg := "all cert discovery methods exhausted for " + target
		execution.Error = &errMsg
		return execution
	}

	execution.RawData = allDomains.rawData
	execution.Results = filterAndFormatDomains(allDomains.domains, target)

	sort.Slice(execution.Results, func(i, j int) bool {
		return execution.Results[i].Value < execution.Results[j].Value
	})

	return execution
}

type domainSource struct {
	NotAfter time.Time
	domain   string
	source   string
}

type collectedDomains struct {
	rawData string
	domains []domainSource
}

func collectAllDomains(ctx context.Context, target string) collectedDomains {
	var result collectedDomains
	rawPayloads := make(map[string]json.RawMessage)

	entries := fetchFromCertspotter(ctx, target)
	if len(entries) > 0 {
		for _, e := range entries {
			result.domains = append(result.domains, domainSource{domain: e.domain, source: "Certspotter", NotAfter: e.notAfter})
		}
		if len(rawPayloads) == 0 {
			rawPayloads["certspotter"] = entries[0].rawData
		}
	}

	entries = fetchFromCrtsh(ctx, target)
	if len(entries) > 0 {
		for _, e := range entries {
			result.domains = append(result.domains, domainSource{domain: e.domain, source: "crt.sh", NotAfter: e.notAfter})
		}
		if len(rawPayloads) == 0 {
			rawPayloads["crtsh"] = entries[0].rawData
		}
	}

	if combined, err := json.Marshal(rawPayloads); err == nil {
		result.rawData = string(combined)
	}

	return result
}

func filterAndFormatDomains(domains []domainSource, target string) []schema.ModuleResult {
	domainMaxNotAfter := make(map[string]time.Time)
	domainSourceInfo := make(map[string]string)

	for _, ds := range domains {
		d := normalizeDomain(ds.domain)
		if !isValidSubdomain(d, target) {
			continue
		}

		if ds.NotAfter.After(domainMaxNotAfter[d]) {
			domainMaxNotAfter[d] = ds.NotAfter
			domainSourceInfo[d] = ds.source
		}
	}

	now := time.Now()
	var results []schema.ModuleResult
	var ghostDomains []string

	for d, notAfter := range domainMaxNotAfter {
		if notAfter.IsZero() || notAfter.After(now) {
			results = append(results, schema.ModuleResult{
				Type:    "domain",
				Value:   d,
				Context: domainSourceInfo[d],
				Applied: true,
			})

			if !notAfter.IsZero() {
				results = append(results, schema.ModuleResult{
					Type:    "string",
					Value:   notAfter.Format(time.RFC3339),
					Context: domainSourceInfo[d] + " " + d + " expires on",
				})
			}
		} else {
			ghostDomains = append(ghostDomains, d)
		}
	}

	if len(ghostDomains) > 0 {
		sort.Strings(ghostDomains)
		results = append(results, schema.ModuleResult{
			Type:    "string",
			Value:   strings.Join(ghostDomains, ", "),
			Context: "Ghost subdomains",
		})
	}

	return results
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return d
}

func isValidSubdomain(d, target string) bool {
	return d != "" && d != target && strings.HasSuffix(d, "."+target)
}

func doRequestWithRetry(ctx context.Context, reqURL string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("do request: %w", err)
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		//nolint:errcheck // defer body close error is not critical
		_ = resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		if isTemporaryError(resp.StatusCode) {
			lastErr = fmt.Errorf("temporary status %d", resp.StatusCode)
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		return nil, fmt.Errorf("hard failure status %d: %s", resp.StatusCode, string(body))
	}

	return nil, lastErr
}

func isTemporaryError(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

type certspotterResponse []struct {
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names"`
}

type domainEntry struct {
	domain   string
	notAfter time.Time
	rawData  json.RawMessage
}

func fetchFromCertspotter(ctx context.Context, target string) []domainEntry {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(target) + "&include_subdomains=true&expand=dns_names"
	body, err := doRequestWithRetry(ctx, u)
	if err != nil {
		return nil
	}

	var records certspotterResponse
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}

	var entries []domainEntry
	for _, rec := range records {
		notAfter := parseCertTimestamp(rec.NotAfter)
		for _, name := range rec.DNSNames {
			entries = append(entries, domainEntry{
				domain:   name,
				notAfter: notAfter,
				rawData:  body,
			})
		}
	}
	return entries
}

type crtshRecord struct {
	NameValue string `json:"name_value"`
	NotAfter  string `json:"not_after"`
}

func fetchFromCrtsh(ctx context.Context, target string) []domainEntry {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(target) + "&output=json"
	body, err := doRequestWithRetry(ctx, u)
	if err != nil {
		return nil
	}

	var records []crtshRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil
	}

	var entries []domainEntry
	for _, rec := range records {
		notAfter := parseCertTimestamp(rec.NotAfter)
		for name := range strings.SplitSeq(rec.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			entries = append(entries, domainEntry{
				domain:   name,
				notAfter: notAfter,
				rawData:  body,
			})
		}
	}
	return entries
}

func parseCertTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	if t, err := time.Parse(timeFormatRFC3339, ts); err == nil {
		return t
	}

	if t, err := time.Parse(timeFormatDate, ts); err == nil {
		return t
	}

	return time.Time{}
}
