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

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/httputil"
)

//go:embed default_network.txt
var defaultNetworkConfig []byte

var (
	dohServers   []string
	plainServers []string
	dohIndex     atomic.Uint32
	plainIndex   atomic.Uint32

	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	}
	userAgentIndex atomic.Uint32

	lastUsedMu    sync.RWMutex
	lastUsedDoH   string
	lastUsedPlain string

	// Timeout controls default network dials across modules.
	Timeout = 5 * time.Second
	// HTTPTimeout defines timeout for HTTP API requests (RIPE, etc).
	HTTPTimeout = 30 * time.Second
	// KeepAlive defines connection persistency timeframe.
	KeepAlive = 30 * time.Second
	// MaxRetriesCert defines maximum attempts for domainsbycerts.
	MaxRetriesCert = 3
	// MaxRetriesWhois defines maximum attempts for whois/RDAP.
	MaxRetriesWhois = 3
	// MaxRetriesDNS defines maximum attempts for normal DNS queries.
	MaxRetriesDNS = 3
	// MaxRetriesHT defines maximum attempts for hackertarget API.
	MaxRetriesHT = 3
	// MaxRetriesIPMeta defines maximum attempts for IP metadata lookups.
	MaxRetriesIPMeta = 3
	// MaxRetriesASNMeta defines maximum attempts for ASN metadata lookups.
	MaxRetriesASNMeta = 3
	// TimeoutASNMeta controls HTTP timeout for ASN metadata API lookups.
	TimeoutASNMeta = 30 * time.Second
	// MaxRecursionDepth defines maximum depth for ASN transit chain traversal.
	MaxRecursionDepth = 3
	// AnubisLimit limits the number of subdomains processed from jldc.me.
	AnubisLimit = 1000

	// ShodanDomainHistory includes historical DNS data for Shodan domain lookups.
	ShodanDomainHistory = false
	// ShodanDomainType specifies DNS type for Shodan domain lookups (e.g. A, AAAA, TXT).
	ShodanDomainType = ""
	// ShodanMaxDomainPages limits the number of pages to fetch for Shodan domain lookups.
	ShodanMaxDomainPages = 1
	// ShodanScanSubdomains enables processing of subdomains via the domain endpoint.
	ShodanScanSubdomains = false
	// ShodanIPHistory includes all historical banners for Shodan IP lookups.
	ShodanIPHistory = false
	// ShodanIPMinify returns only ports and general info for Shodan IP lookups.
	ShodanIPMinify = false

	// DNSQueryTimeout bounds simple DoH-only queries (LOC, SSHFP, DNSKEY, etc.).
	DNSQueryTimeout = 10 * time.Second
	// DNSFallbackTimeout bounds DoH + Plain DNS fallback queries (NS, MX, TXT, etc.).
	DNSFallbackTimeout = 15 * time.Second
	// DNSBruteTimeout bounds concurrent brute-force operations (DKIM, SRV, TLSA).
	DNSBruteTimeout = 30 * time.Second
	// DNSConcurrency limits parallel goroutines in brute-force DNS handlers.
	DNSConcurrency = 10
	// CrtshPGTimeout is the timeout for crt.sh direct PostgreSQL connections.
	CrtshPGTimeout = 30 * time.Second
	// RetryBaseDelay is the base pause between HTTP retry attempts across all modules.
	RetryBaseDelay = 2 * time.Second

	// DisableMailcryptoBruteForce prevents domains and subdomains from being routed to mailcrypto.
	DisableMailcryptoBruteForce = true

	// VirustotalScanSubdomains enables processing of subdomains via the VirusTotal domain endpoint.
	VirustotalScanSubdomains = false

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
	initOptionMaps()
	if strings.HasSuffix(os.Args[0], ".test") {
		parseConfig(string(defaultNetworkConfig))
		return
	}

	configDir := "configs"
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		parseConfig(string(defaultNetworkConfig))
		return
	}

	configPath := filepath.Clean(filepath.Join(configDir, "network.txt"))
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			if writeErr := os.WriteFile(configPath, defaultNetworkConfig, 0o600); writeErr != nil && isDebug() {
				fmt.Fprintf(os.Stderr, "[resolver-debug] failed to write default config: %v\n", writeErr)
			}
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
		dohServers = []string{
			constants.DNSResolverDoHCloudflare,
			constants.DNSResolverDoHGoogle,
			constants.DNSResolverDoHAdGuard,
			constants.DNSResolverDoHMozillaCloudflare,
			constants.DNSResolverDoHSB,
		}
	}
	if len(plainServers) == 0 {
		plainServers = []string{
			constants.DNSResolverCloudflarePrimary,
			constants.DNSResolverGooglePrimary,
			constants.DNSResolverQuad9Primary,
			constants.DNSResolverAdGuardPrimary,
			constants.DNSResolverDNSWatchPrimary,
			constants.DNSResolverResolver19318398154,
			constants.DNSResolverLevel3Primary,
			constants.DNSResolverCloudflareSecondary,
			constants.DNSResolverGoogleSecondary,
			constants.DNSResolverQuad9Secondary,
			constants.DNSResolverAdGuardSecondary,
			constants.DNSResolverDNSWatchSecondary,
			constants.DNSResolverResolver185121177177,
			constants.DNSResolverLevel3Secondary,
		}
	}
}

var durationOptions map[string]*time.Duration

var boolOptions map[string]*bool

var intOptions map[string]*int

var stringOptions map[string]*string

func initOptionMaps() {
	durationOptions = map[string]*time.Duration{
		"Timeout":            &Timeout,
		"KeepAlive":          &KeepAlive,
		"TimeoutASNMeta":     &TimeoutASNMeta,
		"DNSQueryTimeout":    &DNSQueryTimeout,
		"DNSFallbackTimeout": &DNSFallbackTimeout,
		"DNSBruteTimeout":    &DNSBruteTimeout,
		"CrtshPGTimeout":     &CrtshPGTimeout,
		"RetryBaseDelay":     &RetryBaseDelay,
		"HTTPTimeout":        &HTTPTimeout,
	}
	boolOptions = map[string]*bool{
		"DisableMailcryptoBruteForce": &DisableMailcryptoBruteForce,
		"VirustotalScanSubdomains":    &VirustotalScanSubdomains,
		"ShodanDomainHistory":         &ShodanDomainHistory,
		"ShodanScanSubdomains":        &ShodanScanSubdomains,
		"ShodanIPHistory":             &ShodanIPHistory,
		"ShodanIPMinify":              &ShodanIPMinify,
	}
	intOptions = map[string]*int{
		"MaxRetriesCert":       &MaxRetriesCert,
		"MaxRetriesWhois":      &MaxRetriesWhois,
		"MaxRetriesDNS":        &MaxRetriesDNS,
		"MaxRetriesHT":         &MaxRetriesHT,
		"MaxRetriesIPMeta":     &MaxRetriesIPMeta,
		"MaxRetriesASNMeta":    &MaxRetriesASNMeta,
		"MaxRecursionDepth":    &MaxRecursionDepth,
		"AnubisLimit":          &AnubisLimit,
		"ShodanMaxDomainPages": &ShodanMaxDomainPages,
		"DNSConcurrency":       &DNSConcurrency,
	}
	stringOptions = map[string]*string{
		"ShodanDomainType": &ShodanDomainType,
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

	if target, ok := durationOptions[key]; ok {
		parseDurationOption(val, target)
		return
	}
	if target, ok := boolOptions[key]; ok {
		parseBoolOption(val, target)
		return
	}
	if target, ok := intOptions[key]; ok {
		parseIntOption(val, target)
		return
	}
	if target, ok := stringOptions[key]; ok {
		*target = val
	}
}

func parseDurationOption(val string, target *time.Duration) {
	if v, err := strconv.Atoi(val); err == nil && v > 0 {
		*target = time.Duration(v) * time.Second
	}
}

func parseBoolOption(val string, target *bool) {
	if b, err := strconv.ParseBool(val); err == nil {
		*target = b
	}
}

func parseIntOption(val string, target *int) {
	if v, err := strconv.Atoi(val); err == nil && v > 0 {
		*target = v
	}
}

func resolveNextDoH() string {
	idx := dohIndex.Add(1)
	server := dohServers[int(idx)%len(dohServers)]

	lastUsedMu.Lock()
	lastUsedDoH = server
	lastUsedMu.Unlock()

	return server
}

func resolveNextPlain() string {
	idx := plainIndex.Add(1)
	server := plainServers[int(idx)%len(plainServers)]

	lastUsedMu.Lock()
	lastUsedPlain = server
	lastUsedMu.Unlock()

	return server
}

// GetRandomUserAgent returns a rotating User-Agent string for HTTP requests.
func GetRandomUserAgent() string {
	idx := userAgentIndex.Add(1)
	return userAgents[int(idx)%len(userAgents)]
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

// DoHDnsRecord represents a JSON DNS response answer.
type DoHDnsRecord struct {
	Name string `json:"name"`
	Data string `json:"data"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
}

// DoHResponse represents a JSON DNS response payload.
type DoHResponse struct {
	Answer    []DoHDnsRecord `json:"Answer"`
	Authority []DoHDnsRecord `json:"Authority"`
	Status    int            `json:"Status"`
}

// dohStatusError wraps non-2xx DoH HTTP responses with classification metadata,
// enabling callers to differentiate rate limits from transient/permanent failures.
type dohStatusError struct {
	code   int
	action httputil.ResponseAction
}

func (e *dohStatusError) Error() string {
	return fmt.Sprintf("doh status %d", e.code)
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
		if cerr := resp.Body.Close(); cerr != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[resolver-debug] warning: failed to close cache fetch body: %v\n", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, &dohStatusError{code: resp.StatusCode, action: httputil.ClassifyStatus(resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}

	var dohResp DoHResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, body, fmt.Errorf("unmarshal doh response: %w", err)
	}

	if dohResp.Status != 0 && dohResp.Status != 3 {
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

// QueryDoHDns queries the target using DoH and returns the raw JSON response.
func QueryDoHDns(ctx context.Context, target string, qtype int) (*DoHResponse, []byte, error) {
	initResolver()
	var lastErr error

	for attempt := range dohServers {
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
		if cerr := resp.Body.Close(); cerr != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[resolver-debug] warning: failed to close DoH body: %v\n", cerr)
		}
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			action := httputil.ClassifyStatus(resp.StatusCode)
			lastErr = &dohStatusError{code: resp.StatusCode, action: action}
			if action == httputil.RateLimit {
				httputil.SleepContext(ctx, httputil.RetryDelay(action, attempt, RetryBaseDelay))
			}
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

// ResolveRecord performs a DNS query with DoH and optional Plain DNS fallback.
func ResolveRecord(ctx context.Context, target string, qtype int, plainFallback func(context.Context, *net.Resolver) ([]string, error)) (records []string, raw []byte, err error) {
	initResolver()
	var lastErr error

	for attempt := 1; attempt <= MaxRetriesDNS; attempt++ {
		server := resolveNextDoH()
		recs, rData, rErr := resolveDoH(ctx, server, target, qtype)
		if rErr == nil {
			return recs, rData, nil
		}
		lastErr = rErr
		var statusErr *dohStatusError
		if errors.As(rErr, &statusErr) {
			if statusErr.action == httputil.Abort {
				break
			}
			if statusErr.action == httputil.RateLimit && attempt < MaxRetriesDNS {
				httputil.SleepContext(ctx, httputil.RetryDelay(httputil.RateLimit, attempt-1, RetryBaseDelay))
			}
		}
	}

	if plainFallback == nil {
		return nil, nil, fmt.Errorf("all DoH resolution attempts failed, last error: %w", lastErr)
	}

	for attempt := 1; attempt <= MaxRetriesDNS; attempt++ {
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

// ResolveIP rotates through configured DNS servers to resolve IP addresses with retries.
func ResolveIP(ctx context.Context, target string) (ips []string, raw []byte, err error) {
	initResolver()
	var lastErr error

	ips, raw, err = attemptDoHResolution(ctx, target)
	if err == nil {
		return ips, raw, nil
	}
	lastErr = err

	ips, err = attemptPlainResolution(ctx, target)
	if err == nil {
		return ips, nil, nil
	}

	if !errors.Is(err, errPlainNXDOMAIN) {
		lastErr = err
	}

	if lastErr != nil {
		return nil, nil, fmt.Errorf("all resolution attempts failed, last error: %w", lastErr)
	}
	return nil, nil, errors.New("all resolution attempts failed")
}

var errPlainNXDOMAIN = errors.New("nxdomain")

func attemptDoHResolution(ctx context.Context, target string) (ips []string, raw []byte, err error) {
	var lastErr error
	for attempt := 1; attempt <= MaxRetriesDNS; attempt++ {
		server := resolveNextDoH()
		ipsA, rawA, errA := resolveDoH(ctx, server, target, 1)
		ipsAAAA, rawAAAA, errAAAA := resolveDoH(ctx, server, target, 28)

		if errA == nil && errAAAA == nil {
			return mergeIPResults(ipsA, ipsAAAA, rawA, rawAAAA)
		}
		if errA != nil {
			lastErr = errA
		} else {
			lastErr = errAAAA
		}
		var statusErr *dohStatusError
		if errors.As(lastErr, &statusErr) {
			if statusErr.action == httputil.Abort {
				break
			}
			if statusErr.action == httputil.RateLimit && attempt < MaxRetriesDNS {
				httputil.SleepContext(ctx, httputil.RetryDelay(httputil.RateLimit, attempt-1, RetryBaseDelay))
			}
		}
	}
	return nil, nil, lastErr
}

func attemptPlainResolution(ctx context.Context, target string) (ips []string, err error) {
	var lastErr error
	for attempt := 1; attempt <= MaxRetriesDNS; attempt++ {
		server := resolveNextPlain()
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: Timeout}
				return d.DialContext(dialCtx, "udp", net.JoinHostPort(server, "53"))
			},
		}

		resolvedIPs, rErr := r.LookupIPAddr(ctx, target)
		if rErr == nil {
			var results []string
			seen := make(map[string]bool)
			for _, ip := range resolvedIPs {
				ipStr := ip.IP.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					results = append(results, ipStr)
				}
			}
			return results, nil
		}

		var dnsErr *net.DNSError
		if errors.As(rErr, &dnsErr) {
			if dnsErr.IsNotFound || strings.Contains(rErr.Error(), "no such host") || strings.Contains(rErr.Error(), "server misbehaving") {
				return nil, errPlainNXDOMAIN
			}
		}
		lastErr = rErr
	}
	return nil, lastErr
}

func mergeIPResults(ipsA, ipsAAAA []string, rawA, rawAAAA []byte) (ips []string, raw []byte, err error) {
	var combined []string
	seen := make(map[string]bool)
	for _, ip := range append(ipsA, ipsAAAA...) {
		if !seen[ip] {
			seen[ip] = true
			combined = append(combined, ip)
		}
	}

	var rawBuf bytes.Buffer
	if len(rawA) > 0 {
		rawBuf.Write(rawA)
	}
	if len(rawAAAA) > 0 {
		if rawBuf.Len() > 0 {
			rawBuf.WriteByte('\n')
		}
		rawBuf.Write(rawAAAA)
	}
	return combined, rawBuf.Bytes(), nil
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

// ReverseIP formats an IP address into the reversed nibble/octet string suitable for in-addr.arpa or other reverse zone queries.
func ReverseIP(target string) (rev string, isIPv4 bool, err error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return "", false, errors.New("invalid IP address")
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0]), true, nil
	}

	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		b := ip[i]
		fmt.Fprintf(&sb, "%x.%x.", b&0xf, b>>4)
	}
	return strings.TrimSuffix(sb.String(), "."), false, nil
}

func isDebug() bool {
	val, ok := GetOption("Debug")
	return ok && val == "true"
}
