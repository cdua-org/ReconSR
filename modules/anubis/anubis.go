// Package anubis discovers subdomains using the jldc.me Anubis API.
package anubis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	moduleName    = "anubis"
	baseURL       = "https://jldc.me/anubis/subdomains/"
	acceptJSON    = "application/json"
	anubisContext = "Anubis DB"
	anubisLimit   = 1000
)

var dbg = debuglog.New(moduleName)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return moduleName
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetDomains: {
				Limit:      3,
				DelayMs:    2000,
				InputTypes: []string{constants.TypeDomain},
			},
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	execs := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		switch f {
		case constants.FuncGetDomains:
			execution = getDomains(data.Target.Value)
		default:
			execution = modutil.NewExecution(f)
			modutil.SetError(&execution, "unsupported function: %v", fmt.Errorf("%s", f))
		}

		execs = append(execs, execution)
	}

	return schema.ModuleOutput{Executions: execs}, nil
}

func fetchAnubisData(ctx context.Context, target string) ([]byte, error) {
	reqURL := baseURL + target
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesHT; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
		req.Header.Set("Accept", acceptJSON)

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dbg.Printf("attempt=%d error=%v", attempt, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("body close error: %v", cerr)
		}

		if err != nil {
			lastErr = err
			dbg.Printf("attempt=%d read body error=%v", attempt, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		action := httputil.ClassifyStatus(resp.StatusCode)
		if action == httputil.Abort {
			return body, fmt.Errorf("hard failure status %d", resp.StatusCode)
		}

		lastErr = fmt.Errorf("retryable status %d", resp.StatusCode)
		delay := httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay)
		dbg.Printf("attempt=%d status=%d action=%d delay=%v", attempt, resp.StatusCode, action, delay)

		if !httputil.SleepContext(ctx, delay) {
			return body, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
	}

	return nil, fmt.Errorf("all API attempts failed: %w", lastErr)
}

func getDomains(target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDomains)

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout*2)
	defer cancel()

	rawData, err := fetchAnubisData(ctx, target)
	if err != nil {
		modutil.SetError(&exec, "%v", err)
		modutil.SetRawFromBytes(&exec, rawData)
		return exec
	}

	modutil.SetRawFromBytes(&exec, rawData)

	var subdomains []string
	if err := json.Unmarshal(rawData, &subdomains); err != nil {
		modutil.SetError(&exec, "failed to unmarshal anubis JSON: %v", err)
		return exec
	}

	limit := resolver.AnubisLimit
	if limit <= 0 {
		limit = anubisLimit
	}

	seen := make(map[string]bool)
	var processedCount int

	for _, rawDomain := range subdomains {
		if processedCount >= limit {
			dbg.Printf("reached anubis limit of %d", limit)
			break
		}

		domain := strings.ToLower(strings.TrimSpace(rawDomain))
		if domain == "" || domain == target {
			continue
		}

		if orgdomain.IsOutOfScope(domain, target) {
			continue
		}

		if strings.HasSuffix(domain, ".in-addr.arpa") || strings.HasSuffix(domain, ".ip6.arpa") {
			continue
		}

		isWildcard := strings.HasPrefix(domain, "*.")
		cleanDomain := domain
		if isWildcard {
			cleanDomain = strings.TrimPrefix(domain, "*.")
		}

		if _, err := validator.Validate(constants.TypeDomain, cleanDomain); err != nil {
			dbg.Printf("skipped invalid domain %q: %v", domain, err)
			continue
		}

		resultValue := cleanDomain
		if seen[domain] {
			continue
		}
		seen[domain] = true
		processedCount++

		result := schema.ModuleResult{
			Type:     constants.TypeSubdomain,
			Category: constants.CategoryNode,
			Value:    resultValue,
			Context:  anubisContext,
			Applied:  true,
		}
		if isWildcard {
			result.Tags = []string{constants.TagWildcard}
			result.Context = domain
		}

		exec.Results = append(exec.Results, result)
	}

	dbg.Printf("target=%q raw_count=%d processed_count=%d", target, len(subdomains), processedCount)

	return exec
}
