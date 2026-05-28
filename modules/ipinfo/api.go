package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var defaultAPIURL = "https://api.ipinfo.io/"

func processCheck(exec *schema.ModuleExecution, targetValue, apiKey string, gen *modutil.LocalIDGenerator) {
	dbg.Printf("%s target=%q", constants.FuncGetIPInfo, targetValue)

	u, err := url.Parse(defaultAPIURL)
	if err != nil {
		dbg.Printf("%s error target=%q stage=url_parse err=%v", constants.FuncGetIPInfo, targetValue, err)
		modutil.SetError(exec, "invalid default API URL: %v", err)
		return
	}

	basePath := "lite/"
	if resolver.IPINFOPaid {
		basePath = "lookup/"
	}
	var joinErr error
	u.Path, joinErr = url.JoinPath(u.Path, basePath, targetValue)
	if joinErr != nil {
		errStr := fmt.Sprintf("failed to join url path: %v", joinErr)
		exec.Error = &errStr
		dbg.Printf("%s error target=%q msg=\"failed to join url path\" err=%v", constants.FuncGetIPInfo, targetValue, joinErr)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	var lastErr error
	var rawData []byte
	var parsed ipinfoResponse

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		body, statusCode, _, err := doRequest(ctx, u.String(), apiKey)
		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=request attempt=%d err=%v", constants.FuncGetIPInfo, targetValue, attempt, lastErr)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			httputil.SleepContext(ctx, httputil.RetryDelay(httputil.Retry, attempt-1, resolver.RetryBaseDelay))
			continue
		}

		rawData = body
		action := httputil.ClassifyStatus(statusCode)
		dbg.Printf("%s target=%q attempt=%d status=%d action=%d", constants.FuncGetIPInfo, targetValue, attempt, statusCode, action)

		if statusCode == http.StatusOK {
			if err := json.Unmarshal(body, &parsed); err != nil {
				lastErr = fmt.Errorf("parse json: %w", err)
				dbg.Printf("%s error target=%q stage=unmarshal attempt=%d err=%v", constants.FuncGetIPInfo, targetValue, attempt, lastErr)
			} else {
				dbg.Printf("%s success target=%q attempt=%d", constants.FuncGetIPInfo, targetValue, attempt)
				lastErr = nil
			}
			break
		}

		if action == httputil.RateLimit {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeInfo,
				Category: constants.CategoryProperty,
				Value:    "monthly API quota exceeded (HTTP 429)",
				Context:  "IPinfo",
				LocalID:  gen.NextID(),
			})
			dbg.Printf("%s warning target=%q stage=quota_exceeded attempt=%d", constants.FuncGetIPInfo, targetValue, attempt)
			modutil.SetRawFromBytes(exec, rawData)
			return
		}

		if action == httputil.Retry {
			lastErr = fmt.Errorf("temporary HTTP status %d", statusCode)
			dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d", constants.FuncGetIPInfo, targetValue, attempt, statusCode)
			httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay))
			continue
		}

		lastErr = fmt.Errorf("unexpected status %d", statusCode)
		dbg.Printf("%s error target=%q stage=response_status attempt=%d status=%d", constants.FuncGetIPInfo, targetValue, attempt, statusCode)
		break
	}

	modutil.SetRawFromBytes(exec, rawData)

	if lastErr != nil {
		modutil.SetError(exec, "%v", lastErr)
		return
	}

	populateResults(exec, &parsed, gen)
}

func doRequest(ctx context.Context, urlStr, apiKey string) (body []byte, statusCode int, headers http.Header, err error) {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if reqErr != nil {
		return nil, 0, nil, fmt.Errorf("create request: %w", reqErr)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, doErr := client.Do(req)
	if doErr != nil {
		return nil, 0, nil, fmt.Errorf("do request: %w", doErr)
	}

	respBody, readErr := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		return nil, 0, nil, fmt.Errorf("read body: %w", readErr)
	}

	return respBody, resp.StatusCode, resp.Header, nil
}
