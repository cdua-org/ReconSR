// Package netlas provides integration with the Netlas API for domain and IPv4 enrichment.
package netlas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var netlasAPIBaseURL = "https://app.netlas.io/api"
var netlasRateLimitDelay = 1100 * time.Millisecond

func (m *netlasModule) waitRateLimit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.lastReqTime)
	if elapsed < netlasRateLimitDelay {
		time.Sleep(netlasRateLimitDelay - elapsed)
	}
	m.lastReqTime = time.Now()
}

func (m *netlasModule) doAPIRequest(exec *schema.ModuleExecution, u, targetValue string, gen *modutil.LocalIDGenerator) (rawBody []byte, ok bool) {
	if m.keyInvalid.Load() {
		dbg.Printf("%s error target=%q state=key_invalid", exec.Function, targetValue)
		m.mu.Lock()
		msg := m.invalidMsg
		m.mu.Unlock()
		if msg == "" {
			msg = "Netlas API Key is invalid or forbidden"
		}
		appendInfoError(exec, msg, gen)
		return nil, false
	}
	if m.quotaBlocked.Load() {
		dbg.Printf("%s error target=%q state=quota_blocked", exec.Function, targetValue)
		m.mu.Lock()
		msg := m.invalidMsg
		m.mu.Unlock()
		if msg == "" {
			msg = "Netlas Quota Exhausted (Not Enough Coins)"
		}
		appendInfoError(exec, msg, gen)
		return nil, false
	}

	var lastStatus int
	var lastBody []byte
	for attempt := range resolver.MaxRetriesNetlas {
		dbg.Printf("%s attempt=%d/%d target=%q", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue)
		m.waitRateLimit()

		body, respStatus, retryNeeded, reqOK := m.executeHTTPRequest(exec, u, attempt, targetValue, gen)
		lastStatus = respStatus
		lastBody = body
		if !reqOK {
			return nil, false
		}
		if !retryNeeded {
			return body, true
		}
	}

	if lastStatus == 429 {
		msg := parseNetlasError(lastBody, "Netlas Rate Limit Exceeded (HTTP 429)")
		appendInfoError(exec, msg, gen)
		return nil, false
	}

	msg := parseNetlasError(lastBody, fmt.Sprintf("Netlas API Error: Max retries exhausted (HTTP %d)", lastStatus))
	appendInfoError(exec, msg, gen)

	modutil.SetError(exec, "max retries exhausted", fmt.Errorf("status: %d", lastStatus))
	return nil, false
}

func (m *netlasModule) executeHTTPRequest(exec *schema.ModuleExecution, u string, attempt int, targetValue string, gen *modutil.LocalIDGenerator) (rawBody []byte, status int, retryNeeded, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		dbg.Printf("%s error stage=create_request err=%v", exec.Function, err)
		modutil.SetError(exec, "create request: %v", err)
		return nil, 0, false, false
	}

	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

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

	rawBody, err = io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("%s error stage=read_body err=%v", exec.Function, err)
		modutil.SetError(exec, "read body: %v", err)
		return nil, 0, false, false
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		m.keyInvalid.Store(true)
		dbg.Printf("%s auth_error attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, fmt.Sprintf("Netlas API Key is invalid or forbidden (HTTP %d)", resp.StatusCode))
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 402 {
		m.quotaBlocked.Store(true)
		dbg.Printf("%s quota_error attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, "Netlas Quota Exhausted (HTTP 402)")
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 429 {
		var e netlasError
		if err := json.Unmarshal(rawBody, &e); err == nil && e.Type == "daily_request_limit_exceeded" {
			m.quotaBlocked.Store(true)
			dbg.Printf("%s quota_error attempt=%d target=%q status=429 type=daily_request_limit", exec.Function, attempt+1, targetValue)
			msg := parseNetlasError(rawBody, "Netlas Daily Request Limit Exceeded (HTTP 429)")
			appendInfoError(exec, msg, gen)
			return nil, resp.StatusCode, false, true
		}
		sleepOnRateLimitNetlas(ctx, resp, attempt)
		dbg.Printf("%s rate_limited attempt=%d/%d target=%q", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue)
		return rawBody, resp.StatusCode, true, true
	}

	if resp.StatusCode == 400 {
		dbg.Printf("%s bad_request attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, "Netlas Bad Request (HTTP 400)")
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 404 {
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		dbg.Printf("%s server_error attempt=%d/%d target=%q status=%d", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue, resp.StatusCode)
		return rawBody, resp.StatusCode, true, true
	}

	return rawBody, resp.StatusCode, false, true
}

func (m *netlasModule) doAPIRequestPOST(exec *schema.ModuleExecution, u string, reqBody []byte, targetValue string, gen *modutil.LocalIDGenerator) (rawBody []byte, ok bool) {
	if m.keyInvalid.Load() {
		dbg.Printf("%s error target=%q state=key_invalid", exec.Function, targetValue)
		m.mu.Lock()
		msg := m.invalidMsg
		m.mu.Unlock()
		if msg == "" {
			msg = "Netlas API Key is invalid or forbidden"
		}
		appendInfoError(exec, msg, gen)
		return nil, false
	}
	if m.quotaBlocked.Load() {
		dbg.Printf("%s error target=%q state=quota_blocked", exec.Function, targetValue)
		m.mu.Lock()
		msg := m.invalidMsg
		m.mu.Unlock()
		if msg == "" {
			msg = "Netlas Quota Exhausted (Not Enough Coins)"
		}
		appendInfoError(exec, msg, gen)
		return nil, false
	}

	var lastStatus int
	var lastBody []byte
	for attempt := range resolver.MaxRetriesNetlas {
		dbg.Printf("%s attempt=%d/%d target=%q (POST)", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue)
		m.waitRateLimit()

		body, respStatus, retryNeeded, reqOK := m.executeHTTPPostRequest(exec, u, reqBody, attempt, targetValue, gen)
		lastStatus = respStatus
		lastBody = body
		if !reqOK {
			return nil, false
		}
		if !retryNeeded {
			return body, true
		}
	}

	if lastStatus == 429 {
		msg := parseNetlasError(lastBody, "Netlas Rate Limit Exceeded (HTTP 429)")
		appendInfoError(exec, msg, gen)
		return nil, false
	}

	msg := parseNetlasError(lastBody, fmt.Sprintf("Netlas API Error: Max retries exhausted (HTTP %d)", lastStatus))
	appendInfoError(exec, msg, gen)

	modutil.SetError(exec, "max retries exhausted", fmt.Errorf("status: %d", lastStatus))
	return nil, false
}

func (m *netlasModule) executeHTTPPostRequest(exec *schema.ModuleExecution, u string, reqBody []byte, attempt int, targetValue string, gen *modutil.LocalIDGenerator) (rawBody []byte, status int, retryNeeded, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.NetlasDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(reqBody))
	if err != nil {
		dbg.Printf("%s error stage=create_request err=%v", exec.Function, err)
		modutil.SetError(exec, "create request: %v", err)
		return nil, 0, false, false
	}

	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.NetlasDownloadTimeout}
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

	rawBody, err = io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("%s error stage=read_body err=%v", exec.Function, err)
		modutil.SetError(exec, "read body: %v", err)
		return nil, 0, false, false
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		m.keyInvalid.Store(true)
		dbg.Printf("%s auth_error attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, fmt.Sprintf("Netlas API Key is invalid or forbidden (HTTP %d)", resp.StatusCode))
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 402 {
		m.quotaBlocked.Store(true)
		dbg.Printf("%s quota_error attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, "Netlas Quota Exhausted (HTTP 402)")
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 429 {
		var e netlasError
		if err := json.Unmarshal(rawBody, &e); err == nil && e.Type == "daily_request_limit_exceeded" {
			m.quotaBlocked.Store(true)
			dbg.Printf("%s quota_error attempt=%d target=%q status=429 type=daily_request_limit", exec.Function, attempt+1, targetValue)
			msg := parseNetlasError(rawBody, "Netlas Daily Request Limit Exceeded (HTTP 429)")
			appendInfoError(exec, msg, gen)
			return nil, resp.StatusCode, false, true
		}
		sleepOnRateLimitNetlas(ctx, resp, attempt)
		dbg.Printf("%s rate_limited attempt=%d/%d target=%q", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue)
		return rawBody, resp.StatusCode, true, true
	}

	if resp.StatusCode == 400 {
		dbg.Printf("%s bad_request attempt=%d target=%q status=%d", exec.Function, attempt+1, targetValue, resp.StatusCode)
		msg := parseNetlasError(rawBody, "Netlas Bad Request (HTTP 400)")
		appendInfoError(exec, msg, gen)
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode == 404 {
		return nil, resp.StatusCode, false, true
	}

	if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
		dbg.Printf("%s server_error attempt=%d/%d target=%q status=%d", exec.Function, attempt+1, resolver.MaxRetriesNetlas, targetValue, resp.StatusCode)
		return rawBody, resp.StatusCode, true, true
	}

	return rawBody, resp.StatusCode, false, true
}

func sleepOnRateLimitNetlas(ctx context.Context, resp *http.Response, attempt int) {
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter != "" {
		if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
			if netlasRateLimitDelay == 0 {
				httputil.SleepContext(ctx, 0)
			} else {
				httputil.SleepContext(ctx, time.Duration(seconds)*time.Second)
			}
			return
		}
	}
	delay := httputil.RetryDelay(httputil.RateLimit, attempt, resolver.NetlasRetryBaseDelay)
	httputil.SleepContext(ctx, delay)
}

func appendInfoError(exec *schema.ModuleExecution, message string, gen *modutil.LocalIDGenerator) {
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    message,
		LocalID:  gen.NextID(),
	})
}

func (m *netlasModule) setInvalidKeyMsg(msg string) {
	m.mu.Lock()
	m.invalidMsg = msg
	m.mu.Unlock()
	m.keyInvalid.Store(true)
}

func (m *netlasModule) executePreflightRequest() (body []byte, statusCode int, success bool) {
	u := netlasAPIBaseURL + "/users/current/"
	for attempt := range resolver.MaxRetriesNetlas {
		m.waitRateLimit()

		ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		if err != nil {
			cancel()
			dbg.Printf("preflight error stage=create_request err=%v", err)
			m.setInvalidKeyMsg("Netlas API Error: Failed to create request")
			return nil, 0, false
		}

		req.Header.Set("Authorization", "Bearer "+m.apiKey)
		req.Header.Set("content-type", "application/json")
		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			dbg.Printf("preflight error stage=do_request err=%v", err)
			m.setInvalidKeyMsg("Netlas API Error: Failed to execute request")
			return nil, 0, false
		}

		var readErr error
		body, readErr = io.ReadAll(resp.Body)
		statusCode = resp.StatusCode
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("preflight body_close_failed err=%v", cerr)
		}
		if readErr != nil {
			cancel()
			dbg.Printf("preflight error stage=read_body err=%v", readErr)
			m.setInvalidKeyMsg("Netlas API Error: Failed to read response")
			return nil, 0, false
		}

		if statusCode >= 500 && statusCode <= 599 {
			dbg.Printf("preflight server_error attempt=%d/%d status=%d", attempt+1, resolver.MaxRetriesNetlas, statusCode)
			httputil.SleepContext(ctx, httputil.RetryDelay(httputil.RateLimit, attempt, resolver.NetlasRetryBaseDelay))
			cancel()
			continue
		}

		if statusCode == 429 {
			dbg.Printf("preflight rate_limited attempt=%d/%d status=%d", attempt+1, resolver.MaxRetriesNetlas, statusCode)
			sleepOnRateLimitNetlas(ctx, resp, attempt)
			cancel()
			continue
		}

		cancel()
		success = true
		break
	}
	return body, statusCode, success
}

func (m *netlasModule) handlePreflightAPI() {
	if m.apiKey == demoIndicator || m.apiKey == "" {
		return
	}

	m.preflightSync.Do(func() {
		body, statusCode, success := m.executePreflightRequest()
		if !success {
			if !m.keyInvalid.Load() {
				dbg.Printf("preflight exhausted retries")
				m.setInvalidKeyMsg(parseNetlasError(body, fmt.Sprintf("Netlas API Error: Max retries exhausted (HTTP %d)", statusCode)))
			}
			return
		}

		switch statusCode {
		case http.StatusOK:
		case http.StatusPaymentRequired:
			dbg.Printf("preflight error stage=quota status=%d", statusCode)
			m.mu.Lock()
			m.quotaBlocked.Store(true)
			m.invalidMsg = parseNetlasError(body, "Netlas Quota Exhausted (HTTP 402)")
			m.mu.Unlock()
			return
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
			dbg.Printf("preflight error stage=auth_or_bad status=%d", statusCode)
			m.setInvalidKeyMsg(parseNetlasError(body, fmt.Sprintf("Netlas API Error (HTTP %d)", statusCode)))
			return
		default:
			dbg.Printf("preflight error stage=status status=%d", statusCode)
			m.setInvalidKeyMsg(parseNetlasError(body, fmt.Sprintf("Netlas API Error (HTTP %d)", statusCode)))
			return
		}

		var info struct {
			Plan struct {
				Coins               int `json:"coins"`
				LimitPerOneDownload int `json:"limit_per_one_download"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(body, &info); err == nil {
			m.mu.Lock()
			m.coins = info.Plan.Coins
			m.limitPerDl = info.Plan.LimitPerOneDownload
			m.mu.Unlock()
			dbg.Printf("preflight success plan_coins=%d limit=%d", info.Plan.Coins, info.Plan.LimitPerOneDownload)
		} else {
			dbg.Printf("preflight error stage=parse err=%v", err)
			m.setInvalidKeyMsg("Netlas API Error: Failed to parse user profile")
		}
	})
}

type netlasError struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func parseNetlasError(body []byte, defaultMsg string) string {
	var e netlasError
	if err := json.Unmarshal(body, &e); err == nil && e.Title != "" {
		if e.Detail != "" {
			return "Netlas API Error: " + e.Title + " - " + e.Detail
		}
		return "Netlas API Error: " + e.Title
	}
	return defaultMsg
}
