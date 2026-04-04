// Package dns_soa provides functionality to extract Start of Authority (SOA) records
// for a given target domain.
package dns_soa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// Name provides the unique identifier used by the dispatcher for routing.
func (m *module) Name() string {
	return "dns_soa"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_soa"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_soa" {
			execution = getSOAData(data.Target.Value)
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

func getSOAData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_soa",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	soa, rawData, err := lookupSOA(ctx, target)

	if err != nil {
		errMsg := "soa lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	if soa == nil {
		return execution
	}

	primaryNS := strings.TrimSuffix(soa.NS, ".")
	nsOutOfScope := !strings.HasSuffix(strings.ToLower(primaryNS), "."+strings.ToLower(target))

	responsibleEmail := formatMbox(soa.Mbox)
	var emailDomain string
	if _, after, found := strings.Cut(responsibleEmail, "@"); found {
		emailDomain = after
	}
	emailOutOfScope := emailDomain != "" && !strings.HasSuffix(strings.ToLower(emailDomain), "."+strings.ToLower(target))

	execution.Results = append(execution.Results,
		schema.ModuleResult{Type: "domain", Value: primaryNS, Context: "Primary NS", OutOfScope: nsOutOfScope},
		schema.ModuleResult{Type: "email", Value: responsibleEmail, Context: "Responsible Email", OutOfScope: emailOutOfScope},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Serial), 10), Context: "Serial"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Refresh), 10), Context: "Refresh"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Retry), 10), Context: "Retry"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Expire), 10), Context: "Expire"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.MinTTL), 10), Context: "Minimum TTL"},
	)

	return execution
}

//nolint:govet // field alignment optimization is negligible here
type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

// SOA represents the parsed SOA record data.
type SOA struct {
	NS      string
	Mbox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

func lookupSOA(ctx context.Context, target string) (*SOA, []byte, error) {
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=6"

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

	var soa *SOA
	for _, ans := range dohResp.Answer {
		if ans.Type == 6 {
			soa = parseSOA(ans.Data)
			break
		}
	}

	return soa, body, nil
}

func parseSOA(data string) *SOA {
	parts := strings.Fields(data)
	if len(parts) < 7 {
		return nil
	}

	return &SOA{
		NS:      parts[0],
		Mbox:    parts[1],
		Serial:  parseUint(parts[2]),
		Refresh: parseUint(parts[3]),
		Retry:   parseUint(parts[4]),
		Expire:  parseUint(parts[5]),
		MinTTL:  parseUint(parts[6]),
	}
}

func parseUint(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func formatMbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")
	if before, _, found := strings.Cut(mbox, "."); found {
		return before + "@" + mbox[len(before)+1:]
	}
	return mbox
}
