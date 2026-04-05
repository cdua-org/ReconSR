// Package dns_ns provides functionality to extract Name Server (NS) records
// for a given target domain.
package dns_ns

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
	return "dns_ns"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_ns"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_ns" {
			execution = getNSData(data.Target.Value)
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

type dohResponse struct {
	Answer []struct {
		Data string `json:"data"`
		Type int    `json:"type"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

func getNSData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_ns",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsRecords, rawData, err := lookupNS(ctx, target)

	if err != nil {
		errMsg := "ns lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	if len(nsRecords) == 0 {
		execution.Results = []schema.ModuleResult{{
			Type:    "string",
			Value:   "No NS",
			Context: "NS Records",
		}}
		return execution
	}

	for _, ns := range nsRecords {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "domain",
			Value:   ns,
			Context: "NS Record",
		})
	}

	return execution
}

func lookupNS(ctx context.Context, target string) (nss []string, rawData []byte, err error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=2"

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
		//nolint:errcheck // defer close error is not critical
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
		if ans.Type == 2 {
			ns := strings.TrimSuffix(ans.Data, ".")
			if ns != "" {
				nss = append(nss, ns)
			}
		}
	}

	return nss, body, nil
}
