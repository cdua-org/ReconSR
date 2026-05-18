package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

var host = "https://stat.ripe.net"

var dbg = debuglog.New("ripestat")

type rawResponse interface {
	setRawJSON(raw string)
}

func debugFunctionName(endpoint string) string {
	switch endpoint {
	case constants.RIPEstatEndpointAbuseContactFinder:
		return constants.FuncGetASNAbuseContacts
	case constants.RIPEstatEndpointASOverview:
		return constants.FuncGetASNInfo
	case constants.RIPEstatEndpointASNNeighbours:
		return constants.FuncGetASNPeers
	case constants.RIPEstatEndpointAnnouncedPrefixes:
		return constants.FuncGetASNPrefixes
	default:
		return endpoint
	}
}

func attemptQuery(ctx context.Context, url, resource, endpoint string, result any, attempt int) error {
	reqCtx, cancel := context.WithTimeout(ctx, resolver.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		dbg.Printf("%s error resource=%q endpoint=%q stage=create_request attempt=%d err=%v", debugFunctionName(endpoint), resource, endpoint, attempt, err)
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		dbg.Printf("%s error resource=%q endpoint=%q stage=do_request attempt=%d err=%v", debugFunctionName(endpoint), resource, endpoint, attempt, err)
		return fmt.Errorf("ripestat request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed resource=%q endpoint=%q err=%v", debugFunctionName(endpoint), resource, endpoint, cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		action := httputil.ClassifyStatus(resp.StatusCode)
		dbg.Printf("%s error resource=%q endpoint=%q stage=response_status attempt=%d status=%d action=%d", debugFunctionName(endpoint), resource, endpoint, attempt, resp.StatusCode, action)
		return fmt.Errorf("http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("%s error resource=%q endpoint=%q stage=read_body attempt=%d err=%v", debugFunctionName(endpoint), resource, endpoint, attempt, err)
		return fmt.Errorf("read body: %w", err)
	}

	if rawSetter, ok := result.(rawResponse); ok {
		rawSetter.setRawJSON(string(body))
	}

	if err := json.Unmarshal(body, result); err != nil {
		dbg.Printf("%s error resource=%q endpoint=%q stage=unmarshal attempt=%d err=%v", debugFunctionName(endpoint), resource, endpoint, attempt, err)
		return fmt.Errorf("unmarshal: %w", err)
	}

	dbg.Printf("%s success resource=%q endpoint=%q attempt=%d", debugFunctionName(endpoint), resource, endpoint, attempt)
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

	dbg.Printf("%s error resource=%q endpoint=%q stage=all_attempts_failed attempts=%d err=%v", debugFunctionName(endpoint), resource, endpoint, maxRetries, lastErr)

	return fmt.Errorf("all attempts failed: %w", lastErr)
}
