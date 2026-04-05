// Package hackertarget provides passive DNS enumeration via the HackerTarget API.
package hackertarget

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

type module struct{}

func (m *module) Name() string {
	return "hackertarget"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_hosts"},
		InputTypes: []string{"domain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_hosts" {
			execution = m.getHosts(data.Target.Value)
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

func (m *module) getHosts(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_hosts",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body, isQuotaLimit := fetchWithRetry(ctx, target)

	if isQuotaLimit {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   "API quota exhausted",
			Context: "HackerTarget",
			Applied: true,
		})
		return execution
	}

	if body != "" {
		execution.RawData = body
		execution.Results = parseHostSearch(body)
	}

	return execution
}

func fetchWithRetry(ctx context.Context, target string) (body string, isQuotaLimit bool) {
	const maxAttempts = 3

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		body, isQuota, errMsg := doRequest(ctx, target)
		if body != "" {
			return body, false
		}

		if isQuota {
			return "", true
		}

		if errMsg != nil && attempt < maxAttempts && sleepContext(ctx, 2*time.Second) {
			continue
		}

		break
	}

	return "", false
}

func doRequest(ctx context.Context, target string) (body string, isQuota bool, errMsg *string) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		errStr := "create request: " + err.Error()
		return "", false, &errStr
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		errStr := "do request: " + err.Error()
		return "", false, &errStr
	}
	defer func() {
		//nolint:errcheck // response body close error is not critical for read-only operations
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		errStr := "critical status " + strconv.Itoa(resp.StatusCode)
		return "", false, &errStr
	}

	if resp.StatusCode != http.StatusOK {
		errStr := "status " + strconv.Itoa(resp.StatusCode)
		return "", false, &errStr
	}

	if isQuotaExceeded(resp.Header) {
		return "", true, nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errStr := "read body: " + err.Error()
		return "", false, &errStr
	}

	if !isValidCSVFormat(string(bodyBytes)) {
		errStr := "invalid response format: " + string(bodyBytes)
		return "", false, &errStr
	}

	return string(bodyBytes), false, nil
}

func isQuotaExceeded(header http.Header) bool {
	apiCount := header.Get("X-Api-Count")
	apiQuota := header.Get("X-Api-Quota")

	if apiCount == "" || apiQuota == "" {
		return false
	}

	count, cErr := strconv.Atoi(apiCount)
	quota, qErr := strconv.Atoi(apiQuota)

	if cErr != nil || qErr != nil {
		return false
	}

	return count >= quota
}

func isValidCSVFormat(body string) bool {
	for line := range strings.SplitSeq(strings.TrimSpace(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return false
		}
		ip := strings.TrimSpace(parts[1])
		return net.ParseIP(ip) != nil
	}
	return true
}

func parseHostSearch(body string) []schema.ModuleResult {
	var results []schema.ModuleResult

	for line := range strings.SplitSeq(strings.TrimSpace(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}
		domain := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])

		if domain != "" {
			results = append(results, schema.ModuleResult{
				Type:    "subdomain",
				Value:   domain,
				Context: "HackerTarget pDNS Record",
			})
		}
		if ip != "" && net.ParseIP(ip) != nil {
			results = append(results, schema.ModuleResult{
				Type:    "ip",
				Value:   ip,
				Context: "HackerTarget Resolved IP",
			})
		}
	}

	return results
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
