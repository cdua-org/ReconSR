package domainsbycerts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var dbg = debuglog.New("certs")

func doRequestWithRetry(ctx context.Context, reqURL string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesCert; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			dbg.Printf("%s error stage=create_request attempt=%d url=%q err=%v", constants.FuncGetDomains, attempt, reqURL, err)
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

		dbg.Printf("%s request attempt=%d url=%q", constants.FuncGetDomains, attempt, reqURL)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("do request: %w", err)
			dbg.Printf("%s error stage=do_request attempt=%d url=%q err=%v", constants.FuncGetDomains, attempt, reqURL, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if closeErr := resp.Body.Close(); closeErr != nil {
			dbg.Printf("%s body_close_failed url=%q err=%v", constants.FuncGetDomains, reqURL, closeErr)
		}

		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			dbg.Printf("%s error stage=read_body attempt=%d url=%q err=%v", constants.FuncGetDomains, attempt, reqURL, err)
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		sample := string(body)
		if len(sample) > 500 {
			sample = sample[:500] + "..."
		}
		dbg.Printf("%s response attempt=%d status=%d body_len=%d body_sample=%s", constants.FuncGetDomains, attempt, resp.StatusCode, len(body), sample)

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		action := httputil.ClassifyStatus(resp.StatusCode)
		if action == httputil.Abort {
			dbg.Printf("%s error stage=response_status attempt=%d url=%q status=%d action=%d", constants.FuncGetDomains, attempt, reqURL, resp.StatusCode, action)
			return nil, fmt.Errorf("hard failure status %d: %s", resp.StatusCode, string(body))
		}

		lastErr = fmt.Errorf("retryable status %d", resp.StatusCode)
		delay := httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay)
		dbg.Printf("%s error stage=response_status attempt=%d url=%q status=%d action=%d delay=%v", constants.FuncGetDomains, attempt, reqURL, resp.StatusCode, action, delay)
		if !httputil.SleepContext(ctx, delay) {
			return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
		}
		continue
	}

	return nil, lastErr
}
