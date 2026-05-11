// Package virustotal provides data from the VirusTotal API v3.
package virustotal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
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
	moduleName       = "virustotal"
	apiServiceName   = "VirusTotal"
	defaultVTDelay   = 15 * time.Second
	vtConfigPath     = "configs/config.txt"
	vtConfigSection  = "[virustotal]"
	vtDelayConfigKey = "delay="
)

var baseURL = "https://www.virustotal.com/api/v3"

var dbg = debuglog.New("vt")

type module struct {
	apiKey     string
	keyInvalid atomic.Bool
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

	inputTypes := []string{constants.TypeIPv4, constants.TypeIPv6, constants.TypeDomain}
	if resolver.VirustotalScanSubdomains {
		inputTypes = append(inputTypes, constants.TypeSubdomain)
	}

	return schema.ModuleCapabilities{
		CustomFunctions: map[string]schema.FunctionCapabilities{
			constants.FuncGetVTApiData: {
				InputTypes: inputTypes,
				Limit:      1,
				DelayMs:    int(defaultVTDelay / time.Millisecond),
			},
		},
	}, nil
}

func (m *module) getDynamicDelay() time.Duration {
	data, err := os.ReadFile(vtConfigPath)
	if err != nil {
		dbg.Printf("getDynamicDelay path=%q fallback=%s err=%v", vtConfigPath, defaultVTDelay, err)
		return defaultVTDelay
	}

	inVTSection := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inVTSection = strings.EqualFold(line, vtConfigSection)
			continue
		}
		if !inVTSection {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != constants.FuncGetVTApiData {
			continue
		}
		for _, field := range fields[1:] {
			value, found := strings.CutPrefix(field, vtDelayConfigKey)
			if !found {
				continue
			}
			delayMs, convErr := strconv.Atoi(value)
			if convErr != nil || delayMs < 0 {
				dbg.Printf("getDynamicDelay invalid_delay=%q err=%v fallback=%s", value, convErr, defaultVTDelay)
				return defaultVTDelay
			}

			resolved := time.Duration(delayMs) * time.Millisecond
			dbg.Printf("getDynamicDelay path=%q resolved=%s", vtConfigPath, resolved)
			return resolved
		}
	}

	dbg.Printf("getDynamicDelay path=%q fallback=%s reason=no_override", vtConfigPath, defaultVTDelay)
	return defaultVTDelay
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution
		if f == constants.FuncGetVTApiData {
			execution = m.getVTApiData(data)
		} else {
			execution = modutil.NewExecution(f)
			modutil.SetError(&execution, "unsupported function: %v", fmt.Errorf("%s", f))
		}
		executions = append(executions, execution)
	}

	return schema.ModuleOutput{Executions: executions}, nil
}

func (m *module) getVTApiData(input schema.ModuleInput) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetVTApiData)

	if m.keyInvalid.Load() {
		msg := "API key invalid (previous 401/403 error)"
		dbg.Printf("getVTApiData target=%q type=%q blocked=true", input.Target.Value, input.Target.Type)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    msg,
			Context:  apiServiceName,
		})
		return exec
	}

	ctx := context.Background()
	target := input.Target.Value
	targetType := input.Target.Type
	delay := m.getDynamicDelay()

	dbg.Printf("getVTApiData target=%q type=%q delay=%s", target, targetType, delay)

	switch targetType {
	case constants.TypeDomain, constants.TypeSubdomain:
		m.processDomain(ctx, target, delay, &exec)
	case constants.TypeIPv4, constants.TypeIPv6:
		m.processIP(ctx, target, delay, &exec)
	default:
		dbg.Printf("getVTApiData target=%q type=%q unsupported=true", target, targetType)
	}

	return exec
}

func (m *module) processDomain(ctx context.Context, target string, delay time.Duration, exec *schema.ModuleExecution) {
	url := fmt.Sprintf("%s/domains/%s", baseURL, target)
	dbg.Printf("processDomain target=%q phase=root_metadata url=%q", target, url)

	data, raw, err := m.doVTRequest(ctx, url)
	if err != nil {
		dbg.Printf("processDomain target=%q phase=root_metadata action=%d err=%v", target, requestAction(err), err)
		modutil.SetError(exec, "domain metadata failed: %v", err)
		return
	}
	exec.RawData += raw
	dbg.Printf("processDomain target=%q phase=root_metadata raw_bytes=%d", target, len(raw))

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractDomainMetadata(attr, target, exec)
		}
	}

	dbg.Printf("processDomain target=%q phase=subdomains sleep=%s", target, delay)
	if !httputil.SleepContext(ctx, delay) {
		dbg.Printf("processDomain target=%q phase=subdomains sleep_cancelled=true", target)
		return
	}

	disableCertExpired := false
	if val, ok := resolver.GetOption("DisableCertExpiredSubdomains"); ok && strings.EqualFold(val, "true") {
		disableCertExpired = true
	}

	var expiredDomains []string
	subURL := fmt.Sprintf("%s/domains/%s/subdomains?limit=40", baseURL, target)
	m.processPaginated(ctx, subURL, delay, exec, func(item map[string]any) {
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

func (m *module) processIP(ctx context.Context, target string, delay time.Duration, exec *schema.ModuleExecution) {
	url := fmt.Sprintf("%s/ip_addresses/%s", baseURL, target)
	dbg.Printf("processIP target=%q phase=metadata url=%q", target, url)

	data, raw, err := m.doVTRequest(ctx, url)
	if err != nil {
		dbg.Printf("processIP target=%q phase=metadata action=%d err=%v", target, requestAction(err), err)
		modutil.SetError(exec, "IP metadata failed: %v", err)
		return
	}
	exec.RawData += raw
	dbg.Printf("processIP target=%q phase=metadata raw_bytes=%d", target, len(raw))

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractIPMetadata(attr, target, exec)
		}
	}

	dbg.Printf("processIP target=%q phase=resolutions sleep=%s", target, delay)
	if !httputil.SleepContext(ctx, delay) {
		dbg.Printf("processIP target=%q phase=resolutions sleep_cancelled=true", target)
		return
	}

	resURL := fmt.Sprintf("%s/ip_addresses/%s/resolutions?limit=40", baseURL, target)
	m.processPaginated(ctx, resURL, delay, exec, func(item map[string]any) {
		m.extractIPResolution(item, target, exec)
	})
}

func (m *module) processPaginated(ctx context.Context, firstURL string, delay time.Duration, exec *schema.ModuleExecution, handler func(map[string]any)) {
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
		if err != nil {
			dbg.Printf("processPaginated page=%d url=%q action=%d err=%v", page, currentURL, requestAction(err), err)
			modutil.SetError(exec, "pagination failed: %v", err)
			return
		}
		exec.RawData += "\n---\n" + raw

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

		dbg.Printf("processPaginated page=%d next=%q sleep=%s", page, next, delay)
		currentURL = next
		page++
		if !httputil.SleepContext(ctx, delay) {
			dbg.Printf("processPaginated page=%d sleep_cancelled=true", page)
			return
		}
	}
}

func (m *module) doVTRequest(ctx context.Context, url string) (data map[string]any, body string, err error) {
	dbg.Printf("doVTRequest url=%q", url)

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if reqErr != nil {
		dbg.Printf("doVTRequest url=%q build_error=%v", url, reqErr)
		return nil, "", &vtRequestError{err: fmt.Errorf("new request: %w", reqErr), action: httputil.Abort}
	}

	req.Header.Set("x-apikey", m.apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, doErr := client.Do(req)
	if doErr != nil {
		dbg.Printf("doVTRequest url=%q request_error=%v", url, doErr)
		return nil, "", &vtRequestError{err: fmt.Errorf("do request: %w", doErr), action: httputil.Retry}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			dbg.Printf("doVTRequest url=%q close_error=%v", url, closeErr)
			if err == nil {
				err = &vtRequestError{err: fmt.Errorf("close response body: %w", closeErr), action: httputil.Retry}
			}
		}
	}()

	dbg.Printf("doVTRequest url=%q status=%d", url, resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		m.keyInvalid.Store(true)
		dbg.Printf("doVTRequest url=%q invalid_api_key=true status=%d", url, resp.StatusCode)
		return nil, "", &vtRequestError{err: fmt.Errorf("HTTP %d: API key invalid", resp.StatusCode), action: httputil.Abort}
	}

	if resp.StatusCode != http.StatusOK {
		action := httputil.ClassifyStatus(resp.StatusCode)
		dbg.Printf("doVTRequest url=%q status=%d action=%d", url, resp.StatusCode, action)
		return nil, "", &vtRequestError{err: fmt.Errorf("HTTP %d", resp.StatusCode), action: action}
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		dbg.Printf("doVTRequest url=%q read_error=%v", url, readErr)
		return nil, "", &vtRequestError{err: fmt.Errorf("read response body: %w", readErr), action: httputil.Retry}
	}
	body = string(bodyBytes)

	if unmarshalErr := json.Unmarshal(bodyBytes, &data); unmarshalErr != nil {
		dbg.Printf("doVTRequest url=%q unmarshal_error=%v", url, unmarshalErr)
		return nil, body, &vtRequestError{err: fmt.Errorf("unmarshal response: %w", unmarshalErr), action: httputil.Abort}
	}

	dbg.Printf("doVTRequest url=%q success bytes=%d", url, len(bodyBytes))
	return data, body, nil
}
