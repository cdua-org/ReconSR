package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

var shodanAPIBaseURL = "https://api.shodan.io"

func (m *shodanModule) waitRateLimit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	elapsed := time.Since(m.lastReqTime)
	if elapsed < 1100*time.Millisecond {
		time.Sleep(1100*time.Millisecond - elapsed)
	}
	m.lastReqTime = time.Now()
}

func (m *shodanModule) handlePreflightAPI() {
	m.waitRateLimit()
	u := fmt.Sprintf("%s/api-info?key=%s", shodanAPIBaseURL, url.QueryEscape(m.apiKey))

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
	if err != nil {
		dbg.Printf("handlePreflightAPI err=%v", err)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
		return
	}
	req.Header.Set("User-Agent", resolver.GetRandomUserAgent())

	client := &http.Client{Timeout: resolver.HTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		dbg.Printf("handlePreflightAPI do_err=%v", err)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
		return
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			dbg.Printf("handlePreflightAPI body_close_err=%v", cerr)
		}
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		dbg.Printf("handlePreflightAPI invalid_key status=%d", resp.StatusCode)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
		return
	default:
		dbg.Printf("handlePreflightAPI status=%d", resp.StatusCode)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		dbg.Printf("handlePreflightAPI read_body_err=%v", err)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
		return
	}

	var info struct {
		QueryCredits int `json:"query_credits"`
	}
	if err := json.Unmarshal(body, &info); err == nil {
		m.mu.Lock()
		m.queryCredits = info.QueryCredits
		m.mu.Unlock()
		dbg.Printf("handlePreflightAPI success credits=%d", info.QueryCredits)
	} else {
		dbg.Printf("handlePreflightAPI parse_err=%v", err)
		m.mu.Lock()
		m.keyInvalid = true
		m.mu.Unlock()
	}
}
