package domainsbycerts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func isDebug() bool {
	val, ok := resolver.GetOption("Debug")
	return ok && strings.EqualFold(val, "true")
}

func doRequestWithRetry(ctx context.Context, reqURL string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var lastErr error
	debug := isDebug()

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		if debug {
			fmt.Fprintf(os.Stderr, "[certs-debug] attempt=%d url=%q\n", attempt, reqURL)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("do request: %w", err)
			if debug {
				fmt.Fprintf(os.Stderr, "[certs-debug] attempt=%d error=%q\n", attempt, err)
			}
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		//nolint:errcheck // defer body close error is not critical
		_ = resp.Body.Close()

		if err != nil {
			lastErr = fmt.Errorf("read body: %w", err)
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		if debug {
			sample := string(body)
			if len(sample) > 500 {
				sample = sample[:500] + "..."
			}
			fmt.Fprintf(os.Stderr, "[certs-debug] attempt=%d status=%d bodyLen=%d bodySample=%s\n", attempt, resp.StatusCode, len(body), sample)
		}

		if resp.StatusCode == http.StatusOK {
			return body, nil
		}

		if isTemporaryError(resp.StatusCode) {
			lastErr = fmt.Errorf("temporary status %d", resp.StatusCode)
			if !sleepContext(ctx, 2*time.Second) {
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			}
			continue
		}

		return nil, fmt.Errorf("hard failure status %d: %s", resp.StatusCode, string(body))
	}

	return nil, lastErr
}

func isTemporaryError(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusBadGateway || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
