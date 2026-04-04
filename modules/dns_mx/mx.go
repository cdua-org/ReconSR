// Package dns_mx provides functionality to extract Mail Exchange (MX) records for a given target domain.
package dns_mx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cdua-org/ReconSR/schema"
)

var dnsServers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"84.200.69.80:53",
	"84.200.70.40:53",
	"193.183.98.154:53",
	"185.121.177.177:53",
	"4.2.2.1:53",
	"4.2.2.2:53",
}

var dnsIndex atomic.Uint32

func getNextDNSServer() string {
	idx := dnsIndex.Add(1)
	//nolint:gosec // slice length is small and known
	pos := int(idx % uint32(len(dnsServers)))
	return dnsServers[pos]
}

func getCustomResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", getNextDNSServer())
		},
	}
}

func getDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  getCustomResolver(),
	}
}

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "dns_mx"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_mx"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_mx" {
			execution = getMXData(data.Target.Value)
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

type mxRecord struct {
	host string
	pref uint16
}

//nolint:govet // field alignment optimization is negligible here
type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

func getMXData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_mx",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mxs, rawData, err := lookupMX(ctx, target)

	if err != nil {
		errMsg := "mx lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	if len(mxs) == 0 {
		execution.Results = []schema.ModuleResult{{
			Type:    "string",
			Value:   "No MX",
			Context: "MX Records",
		}}
		return execution
	}

	sort.Slice(mxs, func(i, j int) bool {
		return mxs[i].pref < mxs[j].pref
	})

	for _, mx := range mxs {
		targetOOS := !strings.HasSuffix(strings.ToLower(mx.host), "."+strings.ToLower(target))

		execution.Results = append(execution.Results,
			schema.ModuleResult{
				Type:       "domain",
				Value:      mx.host,
				Context:    "MX Record",
				OutOfScope: targetOOS,
			},
			schema.ModuleResult{
				Type:    "string",
				Value:   strconv.FormatUint(uint64(mx.pref), 10),
				Context: "MX Priority",
			},
		)
	}

	return execution
}

func lookupMX(ctx context.Context, target string) ([]mxRecord, []byte, error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=15"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	transport := &http.Transport{
		DialContext:         getDialer().DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   7 * time.Second,
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

	var results []mxRecord
	for _, ans := range dohResp.Answer {
		if ans.Type == 15 {
			mx, err := parseMX(ans.Data)
			if err == nil {
				results = append(results, mx)
			}
		}
	}

	return results, body, nil
}

func parseMX(data string) (mxRecord, error) {
	parts := strings.Fields(data)
	if len(parts) < 2 {
		return mxRecord{}, errors.New("invalid MX record format")
	}

	host := strings.TrimSuffix(parts[1], ".")
	if host == "" {
		return mxRecord{}, errors.New("invalid MX record format")
	}

	pref, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return mxRecord{}, fmt.Errorf("parse priority: %w", err)
	}

	return mxRecord{
		host: host,
		pref: uint16(pref),
	}, nil
}
