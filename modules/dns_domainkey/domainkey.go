// Package dns_domainkey provides functionality to query the policy record
// on the _domainkey subdomain of a given target domain.
package dns_domainkey

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "dns_domainkey"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_domainkey"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_domainkey" {
			execution = getDomainKeyData(data.Target.Value)
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

func getDomainKeyData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_domainkey",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	domainkeyTarget := "_domainkey." + target

	records, rawData, err := lookupTXT(ctx, domainkeyTarget)

	if err != nil {
		errMsg := "domainkey lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	if len(records) == 0 {
		execution.Results = []schema.ModuleResult{{
			Type:    "string",
			Value:   "No DomainKey",
			Context: "Old DomainKey Records",
		}}
		return execution
	}

	for _, rec := range records {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "Old DomainKey Record: " + domainkeyTarget,
		})
	}

	return execution
}

func lookupTXT(ctx context.Context, target string) (txts []string, rawData []byte, err error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=16"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{
		Timeout: 7 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("do request: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer body close error is not critical
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, body, fmt.Errorf("unmarshal doh response: %w", err)
	}

	if len(dohResp.Answer) == 0 {
		return nil, body, nil
	}

	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			rec := strings.TrimSpace(ans.Data)
			if rec != "" {
				txts = append(txts, rec)
			}
		}
	}

	return txts, body, nil
}
