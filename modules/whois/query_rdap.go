package whois

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func queryRDAP(ctx context.Context, domain string) (map[string]any, error) {
	url := buildRDAPURL(domain)
	var lastErr error

	for attempt := 1; attempt <= resolver.MaxRetriesWhois; attempt++ {
		data, retriable, err := attemptRDAP(ctx, url)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !retriable {
			break
		}
		if attempt < resolver.MaxRetriesWhois {
			if !httputil.SleepContext(ctx, resolver.RetryBaseDelay) {
				break
			}
			continue
		}
	}

	return nil, lastErr
}

func defaultRDAPClientDo(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	return resp, nil
}

var rdapClientDo = defaultRDAPClientDo

func attemptRDAP(ctx context.Context, url string) (data map[string]any, retriable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, false, fmt.Errorf("create rdap request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	transport := &http.Transport{
		DialContext:         resolver.GetDialer().DialContext,
		TLSHandshakeTimeout: resolver.Timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   resolver.HTTPTimeout,
	}

	resp, err := rdapClientDo(client, req)
	if err != nil {
		return nil, true, fmt.Errorf("rdap do request: %w", err)
	}

	bodyOk := true
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("rdap status %d", resp.StatusCode)
		bodyOk = false
	}

	decodeErr := json.NewDecoder(resp.Body).Decode(&data)
	if cerr := resp.Body.Close(); cerr != nil {
		dbg.Printf("%s rdap_body_close_failed err=%v", constants.FuncGetWhois, cerr)
	}

	if !bodyOk {
		action := httputil.ClassifyStatus(resp.StatusCode)
		retriable := action == httputil.Retry || action == httputil.RateLimit
		return nil, retriable, err
	}

	if decodeErr != nil {
		return nil, true, fmt.Errorf("rdap decode error: %w", decodeErr)
	}

	return data, false, nil
}
