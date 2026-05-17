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

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	moduleName          = "hackertarget"
	apiServiceName      = "HackerTarget"
	hostSearchPath      = "/hostsearch/?q="
	quotaCountHeader    = "X-Api-Count"
	quotaLimitHeader    = "X-Api-Quota"
	quotaExhaustedValue = "API quota exhausted"
	contextPDNSRecord   = "HackerTarget pDNS Record"
	contextResolvedIP   = "HackerTarget Resolved IP"
)

var dbg = debuglog.New("ht")

var apiBaseURL = "https://api.hackertarget.com"

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey(apiServiceName),
	}
}

type module struct {
	apiKey string
}

func (m *module) Name() string {
	return moduleName
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetHosts},
		InputTypes: []string{constants.TypeDomain},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   5,
			DelayMs: 2000,
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == constants.FuncGetHosts {
			execution = m.getHosts(data.Target.Value)
		} else {
			execution = modutil.NewExecution(f)
			errMsg := "unsupported function: " + f
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func (m *module) getHosts(target string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetHosts)

	dbg.Printf("getHosts target=%q", target)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body, isQuotaLimit := fetchWithRetry(ctx, target, m.apiKey)

	dbg.Printf("getHosts target=%q results=%d quota=%v", target, len(execution.Results), isQuotaLimit)

	if isQuotaLimit {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeAPIQuota,
			Category: constants.CategoryProperty,
			Value:    quotaExhaustedValue,
			Context:  apiServiceName,
			Applied:  true,
		})
		return execution
	}

	if body != "" {
		execution.RawData = body
		execution.Results = parseHostSearch(body, target)
	}

	return execution
}

func fetchWithRetry(ctx context.Context, target, apiKey string) (body string, isQuotaLimit bool) {
	for attempt := 1; attempt <= resolver.MaxRetriesHT; attempt++ {
		dbg.Printf("fetchWithRetry attempt=%d/%d target=%q", attempt, resolver.MaxRetriesHT, target)

		body, isQuota, errMsg, action := doRequest(ctx, target, apiKey)
		if body != "" {
			return body, false
		}

		if isQuota {
			return "", true
		}

		if errMsg == nil || attempt >= resolver.MaxRetriesHT {
			break
		}

		if action == httputil.Abort {
			dbg.Printf("fetchWithRetry target=%q abort (permanent %s)", target, *errMsg)
			break
		}

		delay := httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay)
		if !httputil.SleepContext(ctx, delay) {
			break
		}
	}

	return "", false
}

func doRequest(ctx context.Context, target, apiKey string) (body string, isQuota bool, errMsg *string, action httputil.ResponseAction) {
	u := apiBaseURL + hostSearchPath + url.QueryEscape(target)
	if apiKey != "" {
		u += "&apikey=" + url.QueryEscape(apiKey)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		errStr := "create request: " + err.Error()
		dbg.Printf("doRequest target=%q error=%v", target, err)
		return "", false, &errStr, httputil.Abort
	}

	dbg.Printf("doRequest target=%q url=%q", target, u)

	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		errStr := "do request: " + err.Error()
		dbg.Printf("doRequest target=%q error=%v", target, err)
		return "", false, &errStr, httputil.Retry
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			dbg.Printf("body close error: %v", closeErr)
		}
	}()

	dbg.Printf("doRequest target=%q status=%d", target, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		action = httputil.ClassifyStatus(resp.StatusCode)
		errStr := "status " + strconv.Itoa(resp.StatusCode)
		dbg.Printf("doRequest target=%q status=%d action=%v", target, resp.StatusCode, action)
		return "", false, &errStr, action
	}

	if isQuotaExceeded(resp.Header) {
		dbg.Printf("doRequest target=%q quota_exceeded", target)
		return "", true, nil, 0
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errStr := "read body: " + err.Error()
		dbg.Printf("doRequest target=%q error=%v", target, err)
		return "", false, &errStr, httputil.Retry
	}

	if !isValidCSVFormat(string(bodyBytes)) {
		errStr := "invalid response format: " + string(bodyBytes)
		return "", false, &errStr, httputil.Abort
	}

	return string(bodyBytes), false, nil, 0
}

func isQuotaExceeded(header http.Header) bool {
	apiCount := header.Get(quotaCountHeader)
	apiQuota := header.Get(quotaLimitHeader)

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

func parseHostSearch(body, target string) []schema.ModuleResult {
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
		rawDomain := strings.TrimSpace(parts[0])
		rawIP := strings.TrimSpace(parts[1])

		var src *schema.EntityRef
		if rawDomain != "" {
			domainRes, err := validator.Validate(constants.TypeDomain, rawDomain)
			if err != nil {
				continue
			}

			isOOS := orgdomain.IsOutOfScope(domainRes.Value, target)

			results = append(results, schema.ModuleResult{
				Type:       domainRes.Type,
				Category:   constants.CategoryNode,
				Value:      domainRes.Value,
				Context:    contextPDNSRecord,
				OutOfScope: isOOS,
				Tags:       []string{constants.TagPDNS},
			})
			src = &schema.EntityRef{
				Type:  domainRes.Type,
				Value: domainRes.Value,
			}
		}

		if rawIP != "" {
			ipRes, err := validator.Validate(constants.TypeIP, rawIP)
			if err == nil {
				results = append(results, schema.ModuleResult{
					Type:     ipRes.Type,
					Category: constants.CategoryNode,
					Value:    ipRes.Value,
					Context:  contextResolvedIP,
					Source:   src,
				})
			}
		}
	}

	return results
}
