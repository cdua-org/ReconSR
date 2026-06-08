package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
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
		InputTypes: []string{constants.TypeIPv4, constants.TypeIPv6},
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
	exec := modutil.NewExecution(constants.FuncGetIDBShodan)
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

	gen := modutil.NewLocalIDGenerator()
	parseInternetDBResponse(&exec, rawBody, target.Value, gen)
	dbg.Printf("%s success target=%q records=%d", constants.FuncGetIDBShodan, target.Value, len(exec.Results))
	return exec
}

func fetchInternetDB(ctx context.Context, url, target string) (rawBody []byte, statusCode int, err error) {
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesIPMeta; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			dbg.Printf("%s error target=%q stage=create_request attempt=%d err=%v", constants.FuncGetIDBShodan, target, attempt, err)
			return nil, 0, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

		client := &http.Client{Timeout: resolver.HTTPTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=do_request attempt=%d err=%v", constants.FuncGetIDBShodan, target, attempt, err)
			if attempt < resolver.MaxRetriesIPMeta {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		statusCode = resp.StatusCode
		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed target=%q attempt=%d err=%v", constants.FuncGetIDBShodan, target, attempt, cerr)
		}

		if err != nil {
			lastErr = err
			dbg.Printf("%s error target=%q stage=read_body attempt=%d err=%v", constants.FuncGetIDBShodan, target, attempt, err)
			if attempt < resolver.MaxRetriesIPMeta {
				httputil.SleepContext(ctx, resolver.RetryBaseDelay)
			}
			continue
		}

		rawBody = body

		if statusCode == http.StatusOK || statusCode == http.StatusNotFound {
			dbg.Printf("%s target=%q attempt=%d status=%d", constants.FuncGetIDBShodan, target, attempt, statusCode)
			break
		}

		action := httputil.ClassifyStatus(statusCode)
		dbg.Printf("%s target=%q attempt=%d status=%d action=%d", constants.FuncGetIDBShodan, target, attempt, statusCode, action)
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

func parseInternetDBResponse(exec *schema.ModuleExecution, rawBody []byte, target string, gen *modutil.LocalIDGenerator) {
	var parsed internetdbResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		dbg.Printf("%s error target=%q stage=unmarshal err=%v", constants.FuncGetIDBShodan, target, err)
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	for _, h := range parsed.Hostnames {
		appendReverseIPHostnameResult(exec, h, gen)
	}
	for _, p := range parsed.Ports {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypePort,
			Category: constants.CategoryProperty,
			Value:    strconv.Itoa(p),
			LocalID:  gen.NextID(),
		})
	}
	for _, t := range parsed.Tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    t,
			LocalID:  gen.NextID(),
		})
	}
	for _, v := range parsed.Vulns {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVE,
			Category: constants.CategoryProperty,
			Value:    v,
			LocalID:  gen.NextID(),
		})
	}
	if len(parsed.Vulns) > 0 {
		if val, err := validator.Validate(constants.TypeIP, target); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     val.Type,
				Category: constants.CategoryNode,
				Value:    val.Value,
				Tags:     []string{constants.TagCVE},
				LocalID:  gen.NextID(),
			})
		}
	}
	for _, c := range parsed.Cpes {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCPE,
			Category: constants.CategoryProperty,
			Value:    c,
			LocalID:  gen.NextID(),
		})
	}
}
