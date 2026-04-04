// Package dns_dmarc provides functionality to extract DMARC policies
// for a given target domain.
package dns_dmarc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	return "dns_dmarc"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_dmarc"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_dmarc" {
			execution = getDMARCData(data.Target.Value)
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

func getDMARCData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_dmarc",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dmarcTarget := "_dmarc." + target
	records, rawData, err := lookupTXT(ctx, dmarcTarget)

	if err != nil {
		errMsg := "dmarc lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	dmarcRecords := filterDMARC(records)

	if len(dmarcRecords) == 0 {
		execution.Results = []schema.ModuleResult{{
			Type:    "string",
			Value:   "No DMARC",
			Context: "DMARC Records",
		}}
		return execution
	}

	for _, rec := range dmarcRecords {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "DMARC Record",
		})

		parsed := parseDMARC(rec)

		for _, key := range []string{"ruf", "rua"} {
			if val, ok := parsed[key]; ok {
				if email := extractEmail(val); email != "" {
					emailDomain := ""
					if _, after, found := strings.Cut(email, "@"); found {
						emailDomain = after
					}
					isOOS := emailDomain != "" && !strings.HasSuffix(strings.ToLower(emailDomain), "."+strings.ToLower(target))

					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:       "email",
						Value:      email,
						Context:    "DMARC " + strings.ToUpper(key),
						OutOfScope: isOOS,
					})
				}
			}
		}
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

	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			txts = append(txts, ans.Data)
		}
	}

	return txts, body, nil
}

func filterDMARC(records []string) []string {
	var dmarc []string
	for _, rec := range records {
		if strings.HasPrefix(strings.TrimSpace(rec), "v=DMARC1") {
			dmarc = append(dmarc, rec)
		}
	}
	return dmarc
}

func parseDMARC(record string) map[string]string {
	result := make(map[string]string)

	record = strings.TrimSpace(record)
	//nolint:modernize // SplitSeq is more efficient but Split is more widely compatible
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			result[key] = value
		}
	}

	return result
}

func extractEmail(val string) string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "mailto:")
	return val
}
