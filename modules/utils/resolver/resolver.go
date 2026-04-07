// Package resolver provides a unified DNS connection pool and generic network options.
package resolver

import (
	"bytes"
	"context"
	_ "embed"
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

//go:embed default_network.txt
var defaultNetworkConfig []byte

var (
	dohServers   []string
	plainServers []string
	dohIndex     atomic.Uint32
	plainIndex   atomic.Uint32

	lastUsedMu    sync.RWMutex
	lastUsedDoH   string
	lastUsedPlain string

	// Timeout controls default network dials across modules.
	Timeout = 5 * time.Second
	// KeepAlive defines connection persistency timeframe.
	KeepAlive = 30 * time.Second

	// Options acts as a generic configuration dictionary.
	Options = make(map[string]string)

	initOnce sync.Once
)

func init() {
	initResolver()
}

func initResolver() {
	initOnce.Do(func() {
		loadConfig()
	})
}

// GetOption securely retrieves a network configuration key, ensuring initialization.
func GetOption(key string) (string, bool) {
	initResolver()
	val, ok := Options[key]
	return val, ok
}

// GetConfiguredDNS safely returns the active slices of DNS servers for diagnostics.
func GetConfiguredDNS() (doh, plain string) {
	initResolver()
	return strings.Join(dohServers, ", "), strings.Join(plainServers, ", ")
}

func loadConfig() {
	if strings.HasSuffix(os.Args[0], ".test") {
		parseConfig(string(defaultNetworkConfig))
		return
	}

	configDir := "configs"
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		parseConfig(string(defaultNetworkConfig))
		return
	}

	configPath := filepath.Join(configDir, "network.txt")
	//nolint:gosec // Internal path constructed safely
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			//nolint:errcheck // Ignore error writing default config, fallback is used
			_ = os.WriteFile(configPath, defaultNetworkConfig, 0o600)
		}
		parseConfig(string(defaultNetworkConfig))
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
		case "[Options]":
			parseOption(line)
		case "[DoH]":
			doh = append(doh, line)
		case "[Plain]":
			plain = append(plain, line)
		}
	}

	dohServers = doh
	plainServers = plain

	if len(dohServers) == 0 {
		dohServers = []string{"https://dns.cloudflare.com/dns-query", "https://dns.google/resolve"}
	}
	if len(plainServers) == 0 {
		plainServers = []string{"1.1.1.1", "8.8.8.8"}
	}
}

func parseOption(line string) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	Options[key] = val

	switch key {
	case "Timeout":
		if v, err := strconv.Atoi(val); err == nil {
			Timeout = time.Duration(v) * time.Second
		}
	case "KeepAlive":
		if v, err := strconv.Atoi(val); err == nil {
			KeepAlive = time.Duration(v) * time.Second
		}
	}
}

func resolveNextDoH() string {
	idx := dohIndex.Add(1)
	//nolint:gosec // modulo on small length
	server := dohServers[int(idx%uint32(len(dohServers)))]

	lastUsedMu.Lock()
	lastUsedDoH = server
	lastUsedMu.Unlock()

	return server
}

func resolveNextPlain() string {
	idx := plainIndex.Add(1)
	//nolint:gosec // modulo on small length
	server := plainServers[int(idx%uint32(len(plainServers)))]

	lastUsedMu.Lock()
	lastUsedPlain = server
	lastUsedMu.Unlock()

	return server
}

// GetLastUsedDoH safely retrieves the last used DoH domain.
func GetLastUsedDoH() string {
	lastUsedMu.RLock()
	defer lastUsedMu.RUnlock()
	return lastUsedDoH
}

// GetLastUsedPlain safely retrieves the last used Plain DNS server.
func GetLastUsedPlain() string {
	lastUsedMu.RLock()
	defer lastUsedMu.RUnlock()
	return lastUsedPlain
}

// DoHResponse represents a JSON DNS response
type DoHDnsRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type DoHResponse struct {
	Status    int            `json:"Status"`
	Answer    []DoHDnsRecord `json:"Answer"`
	Authority []DoHDnsRecord `json:"Authority"`
}

func resolveDoH(ctx context.Context, endpoint, target string, qtype int) (ips []string, raw []byte, err error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid endpoint url: %w", err)
	}
	q := u.Query()
	q.Set("name", target)
	q.Set("type", strconv.Itoa(qtype))
	q.Set("do", "true") // Request DNSSEC records (NSEC, NSEC3, RRSIG) if available
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: Timeout}
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
	// Also check Authority section, particularly useful for NSEC/NSEC3/SOA on NXDOMAIN
	for _, auth := range dohResp.Authority {
		if auth.Type == qtype {
			results = append(results, auth.Data)
		}
	}
	return results, body, nil
}

// QueryDoHDns performs a raw DoH resolution using the rotation logic and returns the full JSON structure.
// This is essential for DNSSEC/NSEC tasks where the Record Name (e.g., NSEC3 hash) is required alongside the data.
func QueryDoHDns(ctx context.Context, target string, qtype int) (*DoHResponse, []byte, error) {
	initResolver()
	var lastErr error

	for range dohServers {
		server := resolveNextDoH()
		u, err := url.Parse(server)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid endpoint url: %w", err)
		}
		q := u.Query()
		q.Set("name", target)
		q.Set("type", strconv.Itoa(qtype))
		q.Set("do", "true")
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
		if err != nil {
			return nil, nil, fmt.Errorf("create doh request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-json")

		client := &http.Client{Timeout: Timeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("doh status %d", resp.StatusCode)
			continue
		}

		var dohResp DoHResponse
		if err := json.Unmarshal(body, &dohResp); err != nil {
			lastErr = err
			continue
		}

		return &dohResp, body, nil
	}

	return nil, nil, fmt.Errorf("all DoH attempts failed: %w", lastErr)
}

// ResolveRecord handles retries, rotation, and optional fallback from DoH to Plain.
// If plainFallback is nil, it only uses DoH (useful for records like CAA not supported by net.Resolver).
func ResolveRecord(ctx context.Context, target string, qtype int, plainFallback func(context.Context, *net.Resolver) ([]string, error)) (records []string, raw []byte, err error) {
	initResolver()
	var lastErr error

	// Try DoH up to len(dohServers) times
	for range dohServers {
		server := resolveNextDoH()
		recs, rData, rErr := resolveDoH(ctx, server, target, qtype)
		if rErr == nil {
			return recs, rData, nil
		}
		lastErr = rErr
	}

	if plainFallback == nil {
		return nil, nil, fmt.Errorf("all DoH resolution attempts failed, last error: %w", lastErr)
	}

	// Fallback to Plain up to len(plainServers) times
	for range plainServers {
		server := resolveNextPlain()
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: Timeout}
				return d.DialContext(dialCtx, "udp", net.JoinHostPort(server, "53"))
			},
		}

		recs, pErr := plainFallback(ctx, r)
		if pErr == nil {
			return recs, nil, nil
		}

		var dnsErr *net.DNSError
		if errors.As(pErr, &dnsErr) {
			if dnsErr.IsNotFound || strings.Contains(pErr.Error(), "no such host") || strings.Contains(pErr.Error(), "server misbehaving") {
				return nil, nil, nil // NXDOMAIN equivalent, return empty success
			}
		}
		lastErr = pErr
	}

	return nil, nil, fmt.Errorf("all resolution attempts failed, last error: %w", lastErr)
}

// ResolveIP handles retries, rotation and fallbacks from DoH to Plain for A and AAAA records.
//
//nolint:gocyclo,nestif // Core resolution logic with fallback requires moderate complexity
func ResolveIP(ctx context.Context, target string) (ips []string, raw []byte, err error) {
	initResolver()
	var lastErr error

	// Try DoH up to len(dohServers) times
	for range dohServers {
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

	// Fallback to Plain up to len(plainServers) times
	for range plainServers {
		server := resolveNextPlain()
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: Timeout}
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

// GetResolver returns a net.Resolver that rotates through Plain DNS servers from the configuration.
func GetResolver() *net.Resolver {
	initResolver()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			server := resolveNextPlain()
			d := net.Dialer{Timeout: Timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// GetDialer returns a preconfigured net.Dialer equipped with the shared plain DNS resolver rotation.
func GetDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   Timeout,
		KeepAlive: KeepAlive,
		Resolver:  GetResolver(),
	}
}
