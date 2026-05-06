package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("shodan")

func getInternetDBCapabilities() schema.FunctionCapabilities {
	return schema.FunctionCapabilities{
		Limit:      2,
		DelayMs:    1000,
		InputTypes: []string{entityTypeIPv4, entityTypeIPv6},
	}
}

type internetdbResponse struct {
	Cpes      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

var internetDBHost = "https://internetdb.shodan.io"

func getInternetDB(target schema.Entity) schema.ModuleExecution {
	exec := modutil.NewExecution(functionInternetDB)
	url := fmt.Sprintf("%s/%s", internetDBHost, target.Value)

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	rawBody, statusCode, lastErr := fetchInternetDB(ctx, url, target.Value)
	modutil.SetRawFromBytes(&exec, rawBody)

	if statusCode == 0 && lastErr != nil {
		modutil.SetError(&exec, "internetdb request failed: %v", lastErr)
		return exec
	}

	if statusCode == http.StatusNotFound {
		return exec
	}

	if statusCode != http.StatusOK {
		if lastErr != nil {
			modutil.SetError(&exec, "internetdb request failed: %v", lastErr)
		} else {
			modutil.SetError(&exec, "internetdb request failed with status: %d", fmt.Errorf("%d", statusCode))
		}
		return exec
	}

	parseInternetDBResponse(&exec, rawBody, target.Value)
	dbg.Printf(functionInternetDB+" target=%q records=%d", target.Value, len(exec.Results))
	return exec
}

func fetchInternetDB(ctx context.Context, url, target string) (rawBody []byte, statusCode int, err error) {
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			dbg.Printf("get_internetdb attempt=%d target=%q err=%v", attempt, target, err)
			return nil, 0, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dbg.Printf("get_internetdb attempt=%d target=%q err=%v", attempt, target, err)
			if attempt < resolver.MaxRetriesIPMeta {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		statusCode = resp.StatusCode
		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("get_internetdb attempt=%d target=%q body_close_err=%v", attempt, target, cerr)
		}

		if err != nil {
			lastErr = err
			dbg.Printf("get_internetdb attempt=%d target=%q read_body_err=%v", attempt, target, err)
			if attempt < resolver.MaxRetriesIPMeta {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		rawBody = body

		if statusCode == http.StatusOK || statusCode == http.StatusNotFound {
			dbg.Printf("get_internetdb attempt=%d target=%q status=%d", attempt, target, statusCode)
			break
		}

		action := httputil.ClassifyStatus(statusCode)
		dbg.Printf("get_internetdb attempt=%d target=%q status=%d action=%d", attempt, target, statusCode, action)
		if action == httputil.Abort {
			lastErr = fmt.Errorf("http status %d: %s", statusCode, string(body))
			break
		}

		lastErr = fmt.Errorf("http status %d", statusCode)
		if attempt < resolver.MaxRetriesIPMeta {
			if action == httputil.RateLimit {
				httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt-1, resolver.RetryBaseDelay))
			} else {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
		}
	}
	return rawBody, statusCode, lastErr
}

func parseInternetDBResponse(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var parsed internetdbResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		dbg.Printf(functionInternetDB+" target=%q unmarshal_err=%v", target, err)
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	for _, h := range parsed.Hostnames {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "ptr",
			Category: resultCategoryProperty,
			Value:    h,
		})
	}
	for _, p := range parsed.Ports {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultTypePort,
			Category: resultCategoryProperty,
			Value:    strconv.Itoa(p),
		})
	}
	for _, t := range parsed.Tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     "tag",
			Category: resultCategoryProperty,
			Value:    t,
		})
	}
	for _, v := range parsed.Vulns {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultTypeCVE,
			Category: resultCategoryNode,
			Value:    v,
		})
	}
	for _, c := range parsed.Cpes {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultTypeCPE,
			Category: resultCategoryProperty,
			Value:    c,
		})
	}
}
