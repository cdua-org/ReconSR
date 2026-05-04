package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var host = "https://stat.ripe.net"

var dbg = debuglog.New("ripestat")

type rawResponse interface {
	setRawJSON(raw string)
}

func attemptQuery(ctx context.Context, url, resource, endpoint string, result any, attempt int) error {
	reqCtx, cancel := context.WithTimeout(ctx, resolver.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		dbg.Printf("attempt=%d resource=%q endpoint=%q err=%v", attempt, resource, endpoint, err)
		return fmt.Errorf("ripestat request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("body close: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		action := httputil.ClassifyStatus(resp.StatusCode)
		dbg.Printf("attempt=%d resource=%q endpoint=%q status=%d action=%d", attempt, resource, endpoint, resp.StatusCode, action)
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("attempt=%d resource=%q endpoint=%q read_error=%v", attempt, resource, endpoint, err)
		return fmt.Errorf("read body: %w", err)
	}

	if rawSetter, ok := result.(rawResponse); ok {
		rawSetter.setRawJSON(string(body))
	}

	if err := json.Unmarshal(body, result); err != nil {
		dbg.Printf("attempt=%d resource=%q endpoint=%q unmarshal_error=%v", attempt, resource, endpoint, err)
		return fmt.Errorf("unmarshal: %w", err)
	}

	dbg.Printf("attempt=%d resource=%q endpoint=%q success", attempt, resource, endpoint)
	return nil
}

// Query performs a RIPEstat API query with automatic retries.
func Query(ctx context.Context, resource, endpoint string, result any, maxRetries int) error {
	url := fmt.Sprintf("%s/data/%s/data.json?resource=%s", host, endpoint, resource)

	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := attemptQuery(ctx, url, resource, endpoint, result, attempt)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < maxRetries {
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				break
			}
		}
	}

	return fmt.Errorf("all attempts failed: %w", lastErr)
}
