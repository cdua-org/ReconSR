package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func (m *shodanModule) getShodanAPIDomain(target schema.Entity) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetShodanAPIDomain)
	m.preflightOnce.Do(func() { m.handlePreflightAPI() })

	page := 1
	for page <= resolver.ShodanMaxDomainPages {
		m.mu.Lock()
		invalid := m.keyInvalid
		credits := m.queryCredits
		m.mu.Unlock()

		if invalid || credits <= 0 {
			if page == 1 {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeInfo,
					Category: constants.CategoryProperty,
					Value:    "Shodan API key is invalid or query credits exhausted",
				})
			}
			break
		}

		if page > 1 {
			time.Sleep(1100 * time.Millisecond)
		} else {
			m.waitRateLimit()
		}

		rawBody, status, shouldContinue := m.doDomainPageRequest(target.Value, page, &exec)
		if !shouldContinue || rawBody == nil {
			break
		}

		if page == 1 {
			modutil.SetRawFromBytes(&exec, rawBody)
		} else {
			exec.RawData += "\n---\n" + string(rawBody)
		}

		dbg.Printf("%s target=%q page=%d status=%d", constants.FuncGetShodanAPIDomain, target.Value, page, status)

		switch status {
		case http.StatusOK:
			m.mu.Lock()
			m.queryCredits--
			m.mu.Unlock()
			parseShodanAPIDomain(&exec, rawBody, target.Value)

			var shodanResp struct {
				More bool `json:"more"`
			}
			if err := json.Unmarshal(rawBody, &shodanResp); err == nil && shodanResp.More {
				page++
			} else {
				return exec // no more pages
			}

		case http.StatusNotFound:
			return exec // stop entirely

		case http.StatusTooManyRequests:
			modutil.SetError(&exec, "HTTP 429 Rate Limit", nil)
			return exec

		default:
			modutil.SetError(&exec, "http status %d", fmt.Errorf("%d", status))
			return exec
		}
	}

	return exec
}

func (m *shodanModule) doDomainPageRequest(target string, page int, exec *schema.ModuleExecution) (body []byte, status int, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	u := fmt.Sprintf("%s/dns/domain/%s", shodanAPIBaseURL, url.PathEscape(target))
	parsedURL, err := url.Parse(u)
	if err != nil {
		modutil.SetError(exec, "parse url: %v", err)
		return nil, 0, false
	}
	q := parsedURL.Query()
	q.Set("key", m.apiKey)
	if resolver.ShodanDomainHistory {
		q.Set("history", "true")
	}
	if resolver.ShodanDomainType != "" {
		q.Set("type", resolver.ShodanDomainType)
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	parsedURL.RawQuery = q.Encode()
	u = parsedURL.String()

	dbg.Printf("%s request target=%q page=%d url=%q", constants.FuncGetShodanAPIDomain, target, page, u)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		modutil.SetError(exec, "create request: %v", err)
		return nil, 0, false
	}
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		modutil.SetError(exec, "do request: %v", err)
		return nil, 0, false
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("%s body_close_failed err=%v", constants.FuncGetShodanAPIDomain, cerr)
		}
	}()

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		modutil.SetError(exec, "read body: %v", err)
		return nil, 0, false
	}

	return rawBody, resp.StatusCode, true
}
