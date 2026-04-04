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
		InputTypes: []string{"domain", "subdomain"},
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

	var rawDomains []string
	var err error
	var rawData []byte

	rawDomains, rawData, err = fetchFromCertspotter(ctx, target)
	if err != nil || len(rawDomains) == 0 {
		rawDomains, rawData, err = fetchFromCrtsh(ctx, target)
		if err != nil || len(rawDomains) == 0 {
			rawDomains, rawData, err = fetchFromHackerTarget(ctx, target)
		}
	}

	if err != nil && len(rawDomains) == 0 {
		errMsg := "all cert discovery methods exhausted for " + target + ": " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	uniqueDomains := make(map[string]bool)
	var result []string

	for _, d := range rawDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")

		if d != "" && d != target && strings.HasSuffix(d, "."+target) {
			if !uniqueDomains[d] {
				uniqueDomains[d] = true
				result = append(result, d)
			}
		}
	}

	sort.Strings(result)

	for _, d := range result {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "domain",
			Value:   d,
			Context: "Certificate Transparency",
			Applied: true, // Prevents redundant CT queries for already discovered subtrees
		})
	}

	return execution
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
	DNSNames []string `json:"dns_names"`
}

func fetchFromCertspotter(ctx context.Context, target string) (names []string, body []byte, err error) {
	u := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(target) + "&include_subdomains=true&expand=dns_names"
	body, err = doRequestWithRetry(ctx, u)
	if err != nil {
		return nil, nil, err
	}

	var records certspotterResponse
	if err = json.Unmarshal(body, &records); err != nil {
		return nil, body, fmt.Errorf("unmarshal certspotter: %w", err)
	}

	for _, rec := range records {
		names = append(names, rec.DNSNames...)
	}
	return names, body, nil
}

type crtshRecord struct {
	NameValue string `json:"name_value"`
}

func fetchFromCrtsh(ctx context.Context, target string) (names []string, body []byte, err error) {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(target) + "&output=json"
	body, err = doRequestWithRetry(ctx, u)
	if err != nil {
		return nil, nil, err
	}

	var records []crtshRecord
	if err = json.Unmarshal(body, &records); err != nil {
		return nil, body, fmt.Errorf("unmarshal crt.sh: %w", err)
	}

	for _, rec := range records {
		parts := strings.Split(rec.NameValue, "\n")
		names = append(names, parts...)
	}
	return names, body, nil
}

func fetchFromHackerTarget(ctx context.Context, target string) (names []string, body []byte, err error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(target)
	body, err = doRequestWithRetry(ctx, u)
	if err != nil {
		return nil, nil, err
	}

	for line := range strings.SplitSeq(string(body), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) > 0 && parts[0] != "" {
			names = append(names, parts[0])
		}
	}
	return names, body, nil
}
