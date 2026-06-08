package shodan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func (m *shodanModule) getShodanAPIIP(target schema.Entity) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetShodanAPIIP)

	if m.apiKey == demoIndicator {
		return m.getShodanAPIIPDemo(&exec, target)
	}

	m.preflightOnce.Do(func() { m.handlePreflightAPI() })

	m.mu.Lock()
	invalid := m.keyInvalid
	m.mu.Unlock()

	if invalid {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    "Shodan API key is invalid",
		})
		return exec
	}

	m.waitRateLimit()

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/shodan/host/%s", shodanAPIBaseURL, url.PathEscape(target.Value))
	parsedURL, err := url.Parse(u)
	if err != nil {
		modutil.SetError(&exec, "parse url: %v", err)
		return exec
	}
	q := parsedURL.Query()
	q.Set("key", m.apiKey)
	if resolver.ShodanIPHistory {
		q.Set("history", "true")
	}
	if resolver.ShodanIPMinify {
		q.Set("minify", "true")
	}
	parsedURL.RawQuery = q.Encode()
	u = parsedURL.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		modutil.SetError(&exec, "create request: %v", err)
		return exec
	}
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		modutil.SetError(&exec, "do request: %v", sanitizeShodanError(err))
		return exec
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed err=%v", constants.FuncGetShodanAPIIP, cerr)
		}
	}()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		modutil.SetError(&exec, "read body: %v", err)
		return exec
	}
	modutil.SetRawFromBytes(&exec, rawBody)

	dbg.Printf("%s target=%q status=%d", constants.FuncGetShodanAPIIP, target.Value, resp.StatusCode)

	switch resp.StatusCode {
	case http.StatusOK:
		parseShodanAPIIP(&exec, rawBody, target.Value)
	case http.StatusNotFound:
		// ignore
	case http.StatusTooManyRequests:
		modutil.SetError(&exec, "HTTP 429 Rate Limit", nil)
	default:
		modutil.SetError(&exec, "http status %d", fmt.Errorf("%d", resp.StatusCode))
	}

	return exec
}
