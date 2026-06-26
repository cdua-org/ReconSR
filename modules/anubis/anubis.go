// Package anubis discovers subdomains using the anubisdb.com Anubis API.
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
	acceptJSON    = "application/json"
	anubisContext = "Anubis DB"
	anubisLimit   = 10000
)

var dbg = debuglog.New(moduleName)
var baseURL = "https://anubisdb.com/anubis/subdomains/"

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
				DelayMs:    600,
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

func fetchAnubisData(ctx context.Context, target string) (body []byte, statusCode int, err error) {
	reqURL := baseURL + target
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesAnubis; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			dbg.Printf("%s error target=%q stage=create_request attempt=%d err=%v", constants.FuncGetDomains, target, attempt, err)
			return nil, 0, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
		req.Header.Set("Accept", acceptJSON)

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=do_request attempt=%d err=%v", constants.FuncGetDomains, target, attempt, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, 0, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed target=%q err=%v", constants.FuncGetDomains, target, cerr)
		}

		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=read_body attempt=%d err=%v", constants.FuncGetDomains, target, attempt, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, 0, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return body, resp.StatusCode, nil
		}

		action := httputil.ClassifyStatus(resp.StatusCode)
		if action == httputil.Abort {
			dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d action=%d", constants.FuncGetDomains, target, attempt, resp.StatusCode, action)
			return body, resp.StatusCode, fmt.Errorf("hard failure status %d", resp.StatusCode)
		}

		lastErr = fmt.Errorf("retryable status %d", resp.StatusCode)
		delay := httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay)
		dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d action=%d delay=%v", constants.FuncGetDomains, target, attempt, resp.StatusCode, action, delay)

		if !httputil.SleepContext(ctx, delay) {
			return body, resp.StatusCode, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
	}

	return nil, 0, fmt.Errorf("all API attempts failed: %w", lastErr)
}

func getDomains(target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDomains)

	gen := modutil.NewLocalIDGenerator()

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout*2)
	defer cancel()

	rawData, statusCode, err := fetchAnubisData(ctx, target)
	if err != nil {
		if statusCode == http.StatusForbidden {
			modutil.SetRawFromBytes(&exec, rawData)
			exec.Results = append(exec.Results, handle403Result(gen))
			return exec
		}

		modutil.SetError(&exec, "%v", err)
		modutil.SetRawFromBytes(&exec, rawData)
		return exec
	}

	modutil.SetRawFromBytes(&exec, rawData)

	var subdomains []string
	if err := json.Unmarshal(rawData, &subdomains); err != nil {
		dbg.Printf("%s error target=%q stage=unmarshal err=%v", constants.FuncGetDomains, target, err)
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
			dbg.Printf("%s reached_limit=%d target=%q", constants.FuncGetDomains, limit, target)
			break
		}

		domain, cleanDomain, isWildcard, valid := processDomain(rawDomain, target)
		if !valid {
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
			Tags:     []string{constants.TagPDNS},
			LocalID:  gen.NextID(),
		}
		if isWildcard {
			result.Tags = append(result.Tags, constants.TagWildcard)
			result.Context = domain
		}

		exec.Results = append(exec.Results, result)
	}

	dbg.Printf("%s success target=%q raw_count=%d processed_count=%d", constants.FuncGetDomains, target, len(subdomains), processedCount)

	return exec
}

func processDomain(rawDomain, target string) (domain, cleanDomain string, isWildcard, valid bool) {
	domain = strings.ToLower(strings.TrimSpace(rawDomain))
	if domain == "" || domain == target {
		return "", "", false, false
	}

	if orgdomain.IsOutOfScope(domain, target) {
		return "", "", false, false
	}

	if strings.HasSuffix(domain, ".in-addr.arpa") || strings.HasSuffix(domain, ".ip6.arpa") {
		return "", "", false, false
	}

	isWildcard = strings.HasPrefix(domain, "*.")
	cleanDomain = domain
	if isWildcard {
		cleanDomain = strings.TrimPrefix(domain, "*.")
	}

	if _, err := validator.Validate(constants.TypeDomain, cleanDomain); err != nil {
		dbg.Printf("%s skip_invalid_domain=%q err=%v", constants.FuncGetDomains, domain, err)
		return "", "", false, false
	}

	return domain, cleanDomain, isWildcard, true
}

func handle403Result(gen *modutil.LocalIDGenerator) schema.ModuleResult {
	return schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "Access denied (HTTP 403) from Anubis API. Service might be blocking your IP, consider using a VPN.",
		LocalID:  gen.NextID(),
	}
}
