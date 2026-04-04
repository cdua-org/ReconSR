// Package dns_caa provides functionality to extract Certificate Authority
// Authorization (CAA) records for a given target domain.
package dns_caa

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	return "dns_caa"
}

// Capabilities declares the module's contract (inputs and functions) to the system core.
func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_caa"},
		InputTypes: []string{"domain", "subdomain"},
	}, nil
}

// Exec acts as the stateless execution pipeline for incoming requests,
// isolating the core routing from the underlying network extraction logic.
func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_caa" {
			execution = getCAAData(data.Target.Value)
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

func getCAAData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_caa",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	records, rawData, err := lookupCAA(ctx, target)

	if err != nil {
		errMsg := "caa lookup failed: " + err.Error()
		execution.Error = &errMsg
		execution.Results = nil
		return execution
	}

	execution.RawData = string(rawData)

	for _, rec := range records {
		results := parseCAARecord(rec)
		execution.Results = append(execution.Results, results...)
	}

	return execution
}

//nolint:govet // field alignment optimization is negligible here
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func lookupCAA(ctx context.Context, target string) (records []string, rawData []byte, err error) {
	// 257 is the DNS RR type for CAA
	u := "https://dns.google/resolve?name=" + url.QueryEscape(target) + "&type=257"

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
		if ans.Type == 257 {
			records = append(records, ans.Data)
		}
	}

	return records, body, nil
}

var caaRegex = regexp.MustCompile(`(?i)^\d+\s+(issue|issuewild|iodef|issuemail)\s+"(.*)"$`)

func parseCAARecord(data string) []schema.ModuleResult {
	// Handle RFC 3597 hex-encoded format (e.g., "\# 21 00 05 69 73...")
	if strings.HasPrefix(data, "\\#") {
		if decoded, err := decodeHexCAA(data); err == nil {
			data = decoded
		}
	}

	var results []schema.ModuleResult

	results = append(results, schema.ModuleResult{
		Type:    "string",
		Value:   data,
		Context: "CAA Record",
	})

	matches := caaRegex.FindStringSubmatch(data)
	if len(matches) < 3 {
		return results
	}

	tag := strings.ToLower(strings.TrimSpace(matches[1]))
	val := strings.TrimSpace(matches[2])

	switch tag {
	case "issue", "issuewild", "issuemail":
		// e.g., "letsencrypt.org", "pki.goog", "amazon.com"
		parts := strings.SplitN(val, ";", 2)
		domain := strings.TrimSpace(parts[0])
		if domain != "" {
			// Certificate Authorities are external infrastructure - mark as OutOfScope
			results = append(results, schema.ModuleResult{
				Type:       "domain",
				Value:      domain,
				Context:    "Authorized CA (" + tag + ")",
				OutOfScope: true,
			})
		}
	case "iodef":
		// e.g., "mailto:security@example.com" or "http://example.com/abuse"
		if strings.HasPrefix(strings.ToLower(val), "mailto:") {
			email := strings.TrimPrefix(val[7:], "//")
			if email != "" {
				results = append(results, schema.ModuleResult{
					Type:       "email",
					Value:      email,
					Context:    "CAA Violation Report",
					OutOfScope: true, // Email contact for abuse reporting is external infra
				})
			}
		} else if strings.HasPrefix(strings.ToLower(val), "http") {
			results = append(results, schema.ModuleResult{
				Type:    "url",
				Value:   val,
				Context: "CAA Violation Report",
			})
		}
	}

	return results
}

// decodeHexCAA converts RFC 3597 hex-encoded CAA data into standard presentation format.
// Format: \# <length> <hex_data>
// CAA RDATA: <flags:1> <tag_len:1> <tag:N> <value:M>
func decodeHexCAA(raw string) (string, error) {
	parts := strings.Fields(raw)
	if len(parts) < 3 || parts[0] != "\\#" {
		return "", errors.New("invalid hex format")
	}

	hexData := strings.Join(parts[2:], "")
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}

	if len(data) < 2 {
		return "", errors.New("data too short")
	}

	flags := data[0]
	tagLen := int(data[1])
	if len(data) < 2+tagLen {
		return "", errors.New("tag length mismatch")
	}

	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])

	return strconv.Itoa(int(flags)) + " " + tag + " \"" + value + "\"", nil
}
