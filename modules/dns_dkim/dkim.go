// Package dns_dkim provides functionality to perform targeted enumeration
// of common DKIM (DomainKeys Identified Mail) selectors.
package dns_dkim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/schema"
)

var commonSelectors = []string{
	"default",
	"google",
	"mail",
	"s1",
	"s2",
	"k1",
	"k2",
	"selector1",
	"fm1",
	"fm2",
	"pm",
	"protonmail",
	"zoho1",
	"zoho2",
	"smtp",
	"sendgrid",
	"mandrill",
	"pic",
	"x",
	"server",
	"dkim",
}

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "dns_dkim"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_dkim"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_dkim" {
			execution = getDKIMData(data.Target.Value)
		} else {
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

//nolint:govet // field alignment optimization is negligible here
type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

func getDKIMData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_dkim",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type dkimResult struct {
		selector string
		record   string
	}

	results := make(chan dkimResult, len(commonSelectors))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

	for _, selector := range commonSelectors {
		wg.Add(1)

		go func(sel string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			domain := fmt.Sprintf("%s._domainkey.%s", sel, target)
			records, err := lookupTXT(ctx, domain)

			if err != nil || len(records) == 0 {
				return
			}

			for _, rec := range records {
				results <- dkimResult{selector: sel, record: rec}
			}
		}(selector)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var rawData string
	for res := range results {
		if rawData != "" {
			rawData += "\n"
		}
		rawData += res.selector + "._domainkey." + target + ": " + res.record

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   res.record,
			Context: "DKIM Selector: " + res.selector,
		})
	}

	if rawData != "" {
		execution.RawData = rawData
	}

	if len(execution.Results) == 0 {
		execution.Results = []schema.ModuleResult{{
			Type:    "string",
			Value:   "No DKIM",
			Context: "DKIM Records",
		}}
	}

	return execution
}

func lookupTXT(ctx context.Context, target string) ([]string, error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=16"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{
		Timeout: 7 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer body close error is not critical
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, fmt.Errorf("unmarshal doh response: %w", err)
	}

	if len(dohResp.Answer) == 0 {
		return nil, nil
	}

	var txts []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			rec := strings.TrimSpace(ans.Data)
			if strings.HasPrefix(rec, "v=DKIM1") && rec != "" {
				txts = append(txts, rec)
			}
		}
	}

	return txts, nil
}
