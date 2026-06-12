package vuln_lookup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func (m *module) enforceDelay(ctx context.Context) error {
	if resolver.CirclMutexDelayMs <= 0 {
		return nil
	}
	delay := time.Duration(resolver.CirclMutexDelayMs) * time.Millisecond
	elapsed := time.Since(m.lastReqTime)
	if elapsed < delay {
		if !httputil.SleepContext(ctx, delay-elapsed) {
			return fmt.Errorf("context canceled during delay: %w", ctx.Err())
		}
	}
	return nil
}

func (m *module) fetchCircl(ctx context.Context, apiURL, funcName, target string) ([]byte, error) {
	if err := m.enforceDelay(ctx); err != nil {
		return nil, err
	}
	m.lastReqTime = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())
	if m.apiKey != "" {
		req.Header.Set("X-API-KEY", m.apiKey)
	}

	client := &http.Client{Timeout: resolver.HTTPTimeout}

	dlog.Printf("%s stage=request_start target=%q url=%q", funcName, target, apiURL)

	var body []byte
	var lastErr error
	for attempt := range resolver.MaxRetriesCircl {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("do request: %w", err)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dlog.Printf("%s body_close_failed target=%q url=%q err=%v", funcName, target, apiURL, cerr)
		}
		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			continue
		}

		dlog.Printf("%s response_status target=%q status=%d", funcName, target, resp.StatusCode)

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		retry, err2 := processCirclResponse(ctx, resp, attempt, apiURL, funcName, target)
		if !retry {
			if err2 == nil {
				return nil, nil
			}
			return body, err2
		}
		lastErr = err2
		continue
	}

	return body, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func processCirclResponse(ctx context.Context, resp *http.Response, attempt int, apiURL, funcName, target string) (bool, error) {
	action := httputil.ClassifyStatus(resp.StatusCode)
	if action == httputil.Abort {
		if resp.StatusCode == http.StatusNotFound {
			dlog.Printf("%s not_found target=%q url=%q status=%d", funcName, target, apiURL, resp.StatusCode)
			return false, nil
		}
		return false, fmt.Errorf("http %d", resp.StatusCode)
	}
	if action == httputil.RateLimit {
		baseDelay := httputil.RetryDelay(action, attempt, resolver.CirclRetryBaseDelay)
		delay, source := parseRateLimitDelay(resp, baseDelay)
		dlog.Printf("%s rate_limited target=%q url=%q attempt=%d delay=%v source=%s", funcName, target, apiURL, attempt, delay, source)

		if !httputil.SleepContext(ctx, delay) {
			return false, fmt.Errorf("context canceled: %w", ctx.Err())
		}
		return true, errors.New("http 429")
	}
	if action == httputil.Retry {
		dlog.Printf("%s retry_status=%d target=%q url=%q attempt=%d", funcName, resp.StatusCode, target, apiURL, attempt)
		if !httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt, resolver.CirclRetryBaseDelay)) {
			return false, fmt.Errorf("context canceled: %w", ctx.Err())
		}
		return true, fmt.Errorf("http %d", resp.StatusCode)
	}
	return false, fmt.Errorf("unexpected status %d", resp.StatusCode)
}

var circlAPIBaseURL = "https://vulnerability.circl.lu"

func parseRateLimitDelay(resp *http.Response, fallback time.Duration) (delay time.Duration, source string) {
	if retryAfterStr := resp.Header.Get("Retry-After"); retryAfterStr != "" {
		if retryAfterSecs, err := strconv.Atoi(retryAfterStr); err == nil && retryAfterSecs > 0 {
			return time.Duration(retryAfterSecs)*time.Second + time.Second, "retry_after"
		}
	}
	if resetStr := resp.Header.Get("X-RateLimit-Reset"); resetStr != "" {
		if resetUnix, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
			resetTime := time.Unix(resetUnix, 0)
			if timeUntil := time.Until(resetTime); timeUntil > 0 {
				return timeUntil + time.Second, "ratelimit_reset"
			}
		}
	}
	return fallback, "fallback"
}
