// Package leakix provides integration with the LeakIX API.
package leakix

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var leakixAPIBaseURL = "https://leakix.net"

func (m *leakixModule) waitRateLimit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.lastReqTime)
	if elapsed < 1050*time.Millisecond {
		time.Sleep(1050*time.Millisecond - elapsed)
	}
	m.lastReqTime = time.Now()
}

func (m *leakixModule) doAPIRequest(exec *schema.ModuleExecution, u, targetValue string) (rawBody []byte, status int, ok bool) {
	var lastStatus int
	for attempt := range resolver.MaxRetriesLeakIX {
		dbg.Printf("%s attempt=%d/%d target=%q", exec.Function, attempt+1, resolver.MaxRetriesLeakIX, targetValue)
		m.waitRateLimit()

		body, respStatus, retryNeeded, reqOK := m.executeHTTPRequest(exec, u, attempt, targetValue)
		lastStatus = respStatus
		if !reqOK {
			return nil, 0, false
		}
		if !retryNeeded {
			return body, respStatus, true
		}
	}

	modutil.SetError(exec, "max retries exhausted", fmt.Errorf("status: %d", lastStatus))
	return nil, lastStatus, false
}

func (m *leakixModule) executeHTTPRequest(exec *schema.ModuleExecution, u string, attempt int, targetValue string) (rawBody []byte, status int, retryNeeded, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		dbg.Printf("%s error stage=create_request err=%v", exec.Function, err)
		modutil.SetError(exec, "create request: %v", err)
		return nil, 0, false, false
	}
	req.Header.Set("api-key", m.apiKey)
	req.Header.Set("accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	dbg.Printf("%s request_prepared target=%q has_api_key=%t", exec.Function, targetValue, m.apiKey != "")

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		dbg.Printf("%s error stage=do_request err=%v", exec.Function, err)
		modutil.SetError(exec, "do request: %v", err)
		return nil, 0, false, false
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed target=%q err=%v", exec.Function, targetValue, cerr)
		}
	}()

	dbg.Printf("%s response_status target=%q status=%d", exec.Function, targetValue, resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		m.blockedStatus.Store(int32(resp.StatusCode))
		dbg.Printf("%s auth_error attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		sleepOnRateLimit(resp)
		dbg.Printf("%s rate_limited attempt=%d/%d target=%q", exec.Function, attempt+1, resolver.MaxRetriesLeakIX, targetValue)
		return nil, resp.StatusCode, true, true
	}

	rawBody, err = io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("%s error stage=read_body err=%v", exec.Function, err)
		modutil.SetError(exec, "read body: %v", err)
		return nil, 0, false, false
	}

	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		dbg.Printf("%s server_error attempt=%d/%d target=%q status=%d", exec.Function, attempt+1, resolver.MaxRetriesLeakIX, targetValue, resp.StatusCode)
		return nil, resp.StatusCode, true, true
	}

	if resp.StatusCode == http.StatusOK {
		trimmed := bytes.TrimSpace(rawBody)
		if len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' {
			dbg.Printf("%s returned non-json body: %s", exec.Function, string(trimmed))
			return nil, resp.StatusCode, true, true
		}
	}

	return rawBody, resp.StatusCode, false, true
}

func sleepOnRateLimit(resp *http.Response) {
	limitedFor := resp.Header.Get("x-limited-for")
	if limitedFor != "" {
		if d, err := time.ParseDuration(limitedFor); err == nil && d > 0 {
			time.Sleep(d)
			return
		}
	}
	time.Sleep(1050 * time.Millisecond)
}
