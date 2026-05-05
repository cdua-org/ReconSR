package shodan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func (m *shodanModule) getShodanAPIDomain(target schema.Entity) schema.ModuleExecution {
	exec := modutil.NewExecution(functionShodanAPIDomain)
	m.preflightOnce.Do(func() { m.handlePreflightAPI() })

	m.mu.Lock()
	invalid := m.keyInvalid
	credits := m.queryCredits
	m.mu.Unlock()

	if invalid || credits <= 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultTypeInfo,
			Category: resultCategoryProperty,
			Value:    "Shodan API key is invalid or query credits exhausted",
		})
		return exec
	}

	m.waitRateLimit()

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/dns/domain/%s?key=%s", shodanAPIBaseURL, url.PathEscape(target.Value), url.QueryEscape(m.apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		modutil.SetError(&exec, "create request: %v", err)
		return exec
	}
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		modutil.SetError(&exec, "do request: %v", err)
		return exec
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("getShodanAPIDomain body_close_err=%v", cerr)
		}
	}()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		modutil.SetError(&exec, "read body: %v", err)
		return exec
	}
	modutil.SetRawFromBytes(&exec, rawBody)

	dbg.Printf("get_shodan_api_domain target=%q status=%d", target.Value, resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
		m.mu.Lock()
		m.queryCredits--
		m.mu.Unlock()
		parseShodanAPIDomain(&exec, rawBody, target.Value)
	case http.StatusNotFound:
		// Ignore
	case http.StatusTooManyRequests:
		modutil.SetError(&exec, "HTTP 429 Rate Limit", nil)
	default:
		modutil.SetError(&exec, "http status %d", fmt.Errorf("%d", resp.StatusCode))
	}

	return exec
}
