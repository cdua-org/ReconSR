// Package dns_cname provides functionality to extract the canonical name (CNAME)
// for a given target domain.
package dns_cname

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

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "dns_cname"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_cname"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_cname" {
			execution = getCNAMEData(data.Target.Value)
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
		Name string `json:"name"`
		TTL  int    `json:"TTL"`
		Type int    `json:"type"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

func getCNAMEData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_cname",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	var cname, wwwCname string
	var cnameErr, wwwCnameErr error

	wg.Add(1)
	//nolint:modernize // wg.Go has edge cases with context cancellation that cause panics
	go func() {
		defer wg.Done()
		cname, cnameErr = lookupCNAME(ctx, target)
	}()

	wwwTarget := "www." + target
	wg.Add(1)
	//nolint:modernize // wg.Go has edge cases with context cancellation that cause panics
	go func() {
		defer wg.Done()
		wwwCname, wwwCnameErr = lookupCNAME(ctx, wwwTarget)
	}()

	wg.Wait()

	if cnameErr != nil {
		errMsg := "cname lookup failed: " + cnameErr.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	if cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(target, ".")) {
		mu.Lock()
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   cname,
			Context: "CNAME Record",
		})
		mu.Unlock()
	}

	if wwwCnameErr == nil && wwwCname != "" && !strings.EqualFold(wwwCname, strings.TrimSuffix(wwwTarget, ".")) {
		mu.Lock()
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   wwwCname,
			Context: "CNAME Record: www",
		})
		mu.Unlock()
	}

	return execution
}

func lookupCNAME(ctx context.Context, target string) (string, error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=5"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{
		Timeout: 7 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer close error is not critical
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return "", fmt.Errorf("unmarshal doh response: %w", err)
	}

	for _, ans := range dohResp.Answer {
		if ans.Type == 5 {
			cname := strings.TrimSuffix(ans.Data, ".")
			if cname != "" {
				return cname, nil
			}
		}
	}

	return "", nil
}
