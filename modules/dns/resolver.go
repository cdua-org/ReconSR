package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	dohServers   []string
	plainServers []string
	dohIndex     atomic.Uint32
	plainIndex   atomic.Uint32

	initOnce sync.Once
)

const defaultDNSConfig = `[DoH]
https://dns.cloudflare.com/dns-query
https://dns.google/dns-query
https://unfiltered.adguard-dns.com/dns-query
https://dns10.quad9.net/dns-query
https://doh.dns.sb/dns-query
https://freedns.controld.com/p0
https://dns.mullvad.net/dns-query

[Plain]
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
84.200.69.80
84.200.70.40
193.183.98.154
185.121.177.177
4.2.2.1
4.2.2.2
`

func initResolver() {
	initOnce.Do(func() {
		loadConfig()
	})
}

func loadConfig() {
	configDir := "configs"
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		parseConfig(defaultDNSConfig)
		return
	}

	configPath := filepath.Join(configDir, "dns.txt")
	//nolint:gosec // Internal path constructed safely
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			//nolint:errcheck // Ignore error writing default config, fallback is used
			_ = os.WriteFile(configPath, []byte(defaultDNSConfig), 0o600)
		}
		parseConfig(defaultDNSConfig)
		return
	}
	parseConfig(string(data))
}

func parseConfig(content string) {
	var currentSection string
	lines := strings.Split(content, "\n")

	var doh, plain []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line
			continue
		}

		switch currentSection {
		case "[DoH]":
			doh = append(doh, line)
		case "[Plain]":
			plain = append(plain, line)
		}
	}

	dohServers = doh
	plainServers = plain

	if len(dohServers) == 0 {
		dohServers = []string{"https://dns.cloudflare.com/dns-query"}
	}
	if len(plainServers) == 0 {
		plainServers = []string{"1.1.1.1"}
	}
}

func resolveNextDoH() string {
	idx := dohIndex.Add(1)
	//nolint:gosec // modulo on small length
	return dohServers[int(idx%uint32(len(dohServers)))]
}

func resolveNextPlain() string {
	idx := plainIndex.Add(1)
	//nolint:gosec // modulo on small length
	return plainServers[int(idx%uint32(len(plainServers)))]
}

// DoHResponse represents a JSON DNS response
//
//nolint:govet // field alignment
type DoHResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func resolveDoH(ctx context.Context, endpoint, target string, qtype int) (ips []string, raw []byte, err error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid endpoint url: %w", err)
	}
	q := u.Query()
	q.Set("name", target)
	q.Set("type", strconv.Itoa(qtype))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("doh request failed: %w", err)
	}
	defer func() {
		//nolint:errcheck // defer body close
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}

	var dohResp DoHResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, body, fmt.Errorf("unmarshal doh response: %w", err)
	}

	if dohResp.Status != 0 && dohResp.Status != 3 { // 0 = NOERROR, 3 = NXDOMAIN
		return nil, body, fmt.Errorf("dns status: %d", dohResp.Status)
	}

	var results []string
	for _, ans := range dohResp.Answer {
		if ans.Type == qtype {
			results = append(results, ans.Data)
		}
	}
	return results, body, nil
}

// ResolveIP handles retries, rotation and fallbacks from DoH to Plain for A and AAAA records.
//
//nolint:gocyclo,nestif // Core resolution logic with fallback requires moderate complexity
func ResolveIP(ctx context.Context, target string) (ips []string, raw []byte, err error) {
	initResolver()
	var lastErr error

	// Try DoH up to 3 times
	for range 3 {
		server := resolveNextDoH()
		ipsA, rawA, errA := resolveDoH(ctx, server, target, 1)           // A
		ipsAAAA, rawAAAA, errAAAA := resolveDoH(ctx, server, target, 28) // AAAA

		if errA == nil && errAAAA == nil {
			var combined []string
			seen := make(map[string]bool)
			for _, ip := range append(ipsA, ipsAAAA...) {
				if !seen[ip] {
					seen[ip] = true
					combined = append(combined, ip)
				}
			}

			var raw bytes.Buffer
			if len(rawA) > 0 {
				raw.Write(rawA)
			}
			if len(rawAAAA) > 0 {
				if raw.Len() > 0 {
					raw.WriteByte('\n')
				}
				raw.Write(rawAAAA)
			}
			return combined, raw.Bytes(), nil
		}

		if errA != nil {
			lastErr = errA
		} else {
			lastErr = errAAAA
		}
	}

	// Fallback to Plain up to 3 times
	for range 3 {
		server := resolveNextPlain()
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(dialCtx, "udp", net.JoinHostPort(server, "53"))
			},
		}

		ips, err := r.LookupIPAddr(ctx, target)
		if err == nil {
			var results []string
			seen := make(map[string]bool)
			for _, ip := range ips {
				ipStr := ip.IP.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					results = append(results, ipStr)
				}
			}
			return results, nil, nil
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound || strings.Contains(err.Error(), "no such host") || strings.Contains(err.Error(), "server misbehaving") {
				return nil, nil, nil // NXDOMAIN equivalent, just return empty success
			}
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, nil, fmt.Errorf("all resolution attempts failed, last error: %w", lastErr)
	}
	return nil, nil, errors.New("all resolution attempts failed")
}
