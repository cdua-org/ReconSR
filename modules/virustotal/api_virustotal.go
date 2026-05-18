// Package virustotal provides data from the VirusTotal API v3.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/modules/utils/apiconfig"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	moduleName     = "virustotal"
	apiServiceName = "VirusTotal"
)

var baseURL = "https://www.virustotal.com/api/v3"

var dbg = debuglog.New("vt")

type module struct {
	lastReqTime time.Time
	apiKey      string
	mu          sync.Mutex
	keyInvalid  atomic.Bool
}

type vtRequestError struct {
	err    error
	action httputil.ResponseAction
}

func (e *vtRequestError) Error() string {
	return e.err.Error()
}

func (e *vtRequestError) Unwrap() error {
	return e.err
}

func requestAction(err error) httputil.ResponseAction {
	var reqErr *vtRequestError
	if errors.As(err, &reqErr) {
		return reqErr.action
	}

	return httputil.Abort
}

// New instantiates the module for registration.
func New() schema.Module {
	return &module{
		apiKey: apiconfig.GetKey(apiServiceName),
	}
}

func (m *module) Name() string {
	return moduleName
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	if m.apiKey == "" {
		return schema.ModuleCapabilities{}, nil
	}

	domainTypes := []string{constants.TypeDomain}
	if resolver.VirustotalScanSubdomains {
		domainTypes = append(domainTypes, constants.TypeSubdomain)
	}

	return schema.ModuleCapabilities{
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   1,
			DelayMs: 0,
		},
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetVTApiIP: {
				InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
			},
			constants.FuncGetVTApiDomain: {
				InputTypes: domainTypes,
			},
		},
	}, nil
}

func (m *module) waitRateLimit(ctx context.Context) bool {
	delay := time.Duration(resolver.VirustotalDelayMs) * time.Millisecond

	m.mu.Lock()
	now := time.Now()

	var allowedTime time.Time
	if m.lastReqTime.IsZero() || now.Sub(m.lastReqTime) >= delay {
		allowedTime = now
	} else {
		allowedTime = m.lastReqTime.Add(delay)
	}

	m.lastReqTime = allowedTime
	m.mu.Unlock()

	sleepDuration := allowedTime.Sub(now)
	if sleepDuration > 0 {
		dbg.Printf("waitRateLimit duration=%s", sleepDuration)
		return httputil.SleepContext(ctx, sleepDuration)
	}
	return true
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if m.keyInvalid.Load() {
			execution = modutil.NewExecution(f)
			msg := "API key invalid (previous 401/403 error)"
			dbg.Printf("Exec target=%q fn=%q blocked=true", data.Target.Value, f)
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeInfo,
				Category: constants.CategoryProperty,
				Value:    msg,
				Context:  apiServiceName,
			})
			executions = append(executions, execution)
			continue
		}

		ctx := context.Background()
		target := data.Target.Value

		switch f {
		case constants.FuncGetVTApiIP:
			execution = modutil.NewExecution(constants.FuncGetVTApiIP)
			m.processIP(ctx, target, &execution)
		case constants.FuncGetVTApiDomain:
			execution = modutil.NewExecution(constants.FuncGetVTApiDomain)
			m.processDomain(ctx, target, &execution)
		default:
			execution = modutil.NewExecution(f)
			modutil.SetError(&execution, "unsupported function: %v", fmt.Errorf("%s", f))
		}
		executions = append(executions, execution)
	}

	return schema.ModuleOutput{Executions: executions}, nil
}

func (m *module) processDomain(ctx context.Context, target string, exec *schema.ModuleExecution) {
	url := fmt.Sprintf("%s/domains/%s", baseURL, target)
	dbg.Printf("processDomain target=%q phase=root_metadata url=%q", target, url)

	data, raw, err := m.doVTRequest(ctx, url)
	if raw != "" {
		exec.RawData += raw
	}
	if err != nil {
		dbg.Printf("processDomain target=%q phase=root_metadata action=%d err=%v", target, requestAction(err), err)
		modutil.SetError(exec, "domain metadata failed: %v", err)
		return
	}
	dbg.Printf("processDomain target=%q phase=root_metadata raw_bytes=%d", target, len(raw))

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractDomainMetadata(attr, target, exec)
		}
	}

	disableCertExpired := false
	if val, ok := resolver.GetOption("DisableCertExpiredSubdomains"); ok && strings.EqualFold(val, "true") {
		disableCertExpired = true
	}

	var expiredDomains []string
	subURL := fmt.Sprintf("%s/domains/%s/subdomains?limit=40", baseURL, target)
	m.processPaginated(ctx, subURL, exec, func(item map[string]any) {
		if expired := m.extractSubdomain(item, target, disableCertExpired, exec); expired != "" {
			expiredDomains = append(expiredDomains, expired)
		}
	})

	if len(expiredDomains) > 0 {
		sort.Strings(expiredDomains)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCertExpiredSubdomains,
			Category: constants.CategoryProperty,
			Value:    strings.Join(expiredDomains, ", "),
			Context:  "Expired Certificates",
		})
	}
}

func (m *module) processIP(ctx context.Context, target string, exec *schema.ModuleExecution) {
	url := fmt.Sprintf("%s/ip_addresses/%s", baseURL, target)
	dbg.Printf("processIP target=%q phase=metadata url=%q", target, url)

	data, raw, err := m.doVTRequest(ctx, url)
	if raw != "" {
		exec.RawData += raw
	}
	if err != nil {
		dbg.Printf("processIP target=%q phase=metadata action=%d err=%v", target, requestAction(err), err)
		modutil.SetError(exec, "IP metadata failed: %v", err)
		return
	}
	dbg.Printf("processIP target=%q phase=metadata raw_bytes=%d", target, len(raw))

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractIPMetadata(attr, target, exec)
		}
	}

	resURL := fmt.Sprintf("%s/ip_addresses/%s/resolutions?limit=40", baseURL, target)
	m.processPaginated(ctx, resURL, exec, func(item map[string]any) {
		m.extractIPResolution(item, target, exec)
	})
}

func (m *module) processPaginated(ctx context.Context, firstURL string, exec *schema.ModuleExecution, handler func(map[string]any)) {
	currentURL := firstURL
	page := 1
	maxPages := resolver.VirustotalMaxPages

	for currentURL != "" {
		if maxPages > 0 && page > maxPages {
			dbg.Printf("processPaginated page=%d limit_reached max_pages=%d", page, maxPages)
			break
		}

		dbg.Printf("processPaginated page=%d url=%q", page, currentURL)

		data, raw, err := m.doVTRequest(ctx, currentURL)
		if raw != "" {
			exec.RawData += "\n---\n" + raw
			dbg.Printf("processPaginated page=%d raw_saved=true bytes=%d", page, len(raw))
		} else {
			dbg.Printf("processPaginated page=%d raw_saved=false", page)
		}
		if err != nil {
			dbg.Printf("processPaginated page=%d action=%d err=%v", page, requestAction(err), err)
			modutil.SetError(exec, "pagination failed: %v", err)
			return
		}

		items, ok := data["data"].([]any)
		if ok {
			dbg.Printf("processPaginated page=%d items=%d", page, len(items))
			for _, item := range items {
				if itemMap, itemOK := item.(map[string]any); itemOK {
					handler(itemMap)
				}
			}
		}

		links, ok := data["links"].(map[string]any)
		if !ok {
			dbg.Printf("processPaginated page=%d next=absent", page)
			break
		}
		next, ok := links["next"].(string)
		if !ok || next == "" {
			dbg.Printf("processPaginated page=%d next=empty", page)
			break
		}

		currentURL = next
		page++
	}
}

func (m *module) doVTRequest(ctx context.Context, url string) (data map[string]any, body string, err error) {
	maxRetries := resolver.VirustotalMaxRetries
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if !m.waitRateLimit(ctx) {
			return nil, "", &vtRequestError{err: errors.New("context cancelled during rate limit wait"), action: httputil.Abort}
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if reqErr != nil {
			dbg.Printf("doVTRequest attempt=%d build_error=%v", attempt, reqErr)
			return nil, "", &vtRequestError{err: fmt.Errorf("new request: %w", reqErr), action: httputil.Abort}
		}

		req.Close = true
		req.Header.Set("x-apikey", m.apiKey)
		req.Header.Set("Accept", "application/json")

		err = func() error {
			client := &http.Client{Timeout: resolver.HTTPTimeout}
			resp, doErr := client.Do(req)
			if doErr != nil {
				dbg.Printf("doVTRequest attempt=%d request_error=%v", attempt, doErr)
				return &vtRequestError{err: fmt.Errorf("do request: %w", doErr), action: httputil.Retry}
			}
			defer func() {
				if closeErr := resp.Body.Close(); closeErr != nil {
					dbg.Printf("doVTRequest attempt=%d close_error=%v", attempt, closeErr)
				}
			}()

			var processErr error
			data, body, processErr = m.processResponse(resp, attempt)
			return processErr
		}()

		if err == nil {
			dbg.Printf("doVTRequest attempt=%d success bytes=%d", attempt, len(body))
			return data, body, nil
		}

		if attempt == maxRetries {
			break
		}

		var reqErrWrap *vtRequestError
		errors.As(err, &reqErrWrap)
		if reqErrWrap.action == httputil.Abort {
			break
		}

		baseDelay := 2 * time.Second
		if resolver.VirustotalDelayMs == 0 {
			baseDelay = 0
		}
		delay := httputil.RetryDelay(reqErrWrap.action, attempt, baseDelay)

		if delay > 0 {
			dbg.Printf("doVTRequest url=%q attempt=%d action=%d sleep=%s", url, attempt, reqErrWrap.action, delay)
			if !httputil.SleepContext(ctx, delay) {
				return nil, body, &vtRequestError{err: errors.New("context cancelled during retry wait"), action: httputil.Abort}
			}
		}
	}

	return nil, body, err
}

func (m *module) processResponse(resp *http.Response, attempt int) (data map[string]any, body string, err error) {
	dbg.Printf("doVTRequest attempt=%d status=%d", attempt, resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		m.keyInvalid.Store(true)
		dbg.Printf("doVTRequest invalid_api_key=true status=%d", resp.StatusCode)
		return nil, "", &vtRequestError{err: fmt.Errorf("HTTP %d: API key invalid", resp.StatusCode), action: httputil.Abort}
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		dbg.Printf("doVTRequest attempt=%d read_error=%v", attempt, readErr)
		return nil, "", &vtRequestError{err: fmt.Errorf("read response body: %w", readErr), action: httputil.Retry}
	}
	body = string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		action := httputil.ClassifyStatus(resp.StatusCode)
		return nil, body, &vtRequestError{err: fmt.Errorf("HTTP %d", resp.StatusCode), action: action}
	}

	if unmarshalErr := json.Unmarshal(bodyBytes, &data); unmarshalErr != nil {
		dbg.Printf("doVTRequest attempt=%d unmarshal_error=%v", attempt, unmarshalErr)
		return nil, body, &vtRequestError{err: fmt.Errorf("unmarshal response: %w", unmarshalErr), action: httputil.Abort}
	}

	return data, body, nil
}
