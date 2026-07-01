package resolver

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDebugConsoleOption(t *testing.T) {
	oldDebug, hadDebug := Options["Debug"]
	oldDebugConsole, hadDebugConsole := Options["DebugConsole"]
	defer func() {
		if hadDebug {
			Options["Debug"] = oldDebug
		} else {
			delete(Options, "Debug")
		}
		if hadDebugConsole {
			Options["DebugConsole"] = oldDebugConsole
		} else {
			delete(Options, "DebugConsole")
		}
	}()

	tests := []struct {
		name         string
		debug        string
		debugConsole string
		want         bool
	}{
		{name: "unset console", debug: strconv.FormatBool(true), debugConsole: "", want: false},
		{name: "console enabled", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(true), want: true},
		{name: "master disabled", debug: strconv.FormatBool(false), debugConsole: strconv.FormatBool(true), want: false},
		{name: "console false", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(false), want: false},
	}

	for _, tt := range tests {
		Options["Debug"] = tt.debug
		if tt.debugConsole == "" {
			delete(Options, "DebugConsole")
		} else {
			Options["DebugConsole"] = tt.debugConsole
		}

		if got := isDebugConsole(); got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
		isIPv4   bool
		isErr    bool
	}{
		{"192.0.2.1", "1.2.0.192", true, false},
		{"198.51.100.2", "2.100.51.198", true, false},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2", false, false},
		{"invalid", "", false, true},
	}

	for _, tt := range tests {
		rev, isIPv4, err := ReverseIP(tt.ip)
		if (err != nil) != tt.isErr {
			t.Errorf("ip %q: expected error %v, got %v", tt.ip, tt.isErr, err)
		}
		if rev != tt.expected {
			t.Errorf("ip %q: expected %q, got %q", tt.ip, tt.expected, rev)
		}
		if isIPv4 != tt.isIPv4 {
			t.Errorf("ip %q: expected isIPv4 %v, got %v", tt.ip, tt.isIPv4, isIPv4)
		}
	}
}

func TestGetConfiguredDNS(t *testing.T) {
	doh, plain := GetConfiguredDNS()
	if doh == "" && plain == "" {
		t.Log("Both DoH and Plain DNS are empty strings")
	}
}

func setupLoadConfigTest(t *testing.T) func() {
	oldArgs := os.Args
	oldDohServers := dohServers
	oldPlainServers := plainServers
	oldOptions := make(map[string]string)
	maps.Copy(oldOptions, Options)

	os.Args = []string{"fakeapp"}
	if err := os.RemoveAll("configs"); err != nil {
		t.Logf("setup error: %v", err)
	}

	return func() {
		os.Args = oldArgs
		dohServers = oldDohServers
		plainServers = oldPlainServers
		Options = oldOptions
		if err := os.RemoveAll("configs"); err != nil {
			t.Logf("cleanup remove error: %v", err)
		}
	}
}

func TestLoadConfig_MkdirAllError(t *testing.T) {
	defer setupLoadConfigTest(t)()
	err := os.WriteFile("configs", []byte("file"), 0o600)
	if err == nil {
		loadConfig()
		if len(dohServers) == 0 || len(plainServers) == 0 {
			t.Error("Expected fallback to default servers on MkdirAll error")
		}
	}
}

func TestLoadConfig_ReadFileError(t *testing.T) {
	defer setupLoadConfigTest(t)()
	err := os.MkdirAll("configs", 0o700)
	if err == nil {
		loadConfig()
		if _, statErr := os.Stat(filepath.Join("configs", "network.txt")); os.IsNotExist(statErr) {
			t.Error("Expected default config to be written")
		}
	}
}

func TestLoadConfig_WriteFileError(t *testing.T) {
	defer setupLoadConfigTest(t)()
	err := os.MkdirAll("configs", 0o500)
	if err == nil {
		Options["Debug"] = "true"
		Options["DebugConsole"] = "true"
		loadConfig()
		if len(dohServers) == 0 {
			t.Error("Expected fallback to default servers on WriteFile error")
		}
	}
}

func TestLoadConfig_SuccessfulRead(t *testing.T) {
	defer setupLoadConfigTest(t)()
	err := os.MkdirAll("configs", 0o700)
	if err == nil {
		testConfig := "[DoH]\nhttps://test.example.com/dns-query"
		if err := os.WriteFile(filepath.Join("configs", "network.txt"), []byte(testConfig), 0o600); err != nil {
			t.Logf("setup write error: %v", err)
		}
		loadConfig()
		if len(dohServers) != 1 || dohServers[0] != "https://test.example.com/dns-query" {
			t.Errorf("Expected dohServers to match test config, got %v", dohServers)
		}
	}
}

func TestParseConfig_Empty(t *testing.T) {
	oldDohServers := dohServers
	oldPlainServers := plainServers
	defer func() {
		dohServers = oldDohServers
		plainServers = oldPlainServers
	}()

	dohServers = nil
	plainServers = nil

	parseConfig("")

	if len(dohServers) == 0 {
		t.Error("Expected dohServers to be populated with defaults")
	}
	if len(plainServers) == 0 {
		t.Error("Expected plainServers to be populated with defaults")
	}
}

func TestParseOption(t *testing.T) {
	initOptionMaps()

	oldTimeout := Timeout
	oldMaxRetries := MaxRetriesDNS
	oldVTScan := VirustotalScanSubdomains
	oldHunterType := HunterioType

	defer func() {
		Timeout = oldTimeout
		MaxRetriesDNS = oldMaxRetries
		VirustotalScanSubdomains = oldVTScan
		HunterioType = oldHunterType
	}()

	parseOption("invalidLineWithoutEquals")

	parseOption("Timeout=15")
	if Timeout != 15*time.Second {
		t.Errorf("Expected Timeout 15s, got %v", Timeout)
	}
	parseOption("Timeout=invalid")

	parseOption("VirustotalScanSubdomains=true")
	if !VirustotalScanSubdomains {
		t.Error("Expected VirustotalScanSubdomains true")
	}
	parseOption("VirustotalScanSubdomains=invalid")

	parseOption("MaxRetriesDNS=7")
	if MaxRetriesDNS != 7 {
		t.Errorf("Expected MaxRetriesDNS 7, got %d", MaxRetriesDNS)
	}
	parseOption("MaxRetriesDNS=invalid")

	parseOption("HunterioType=personal")
	if HunterioType != "personal" {
		t.Errorf("Expected HunterioType personal, got %s", HunterioType)
	}
}

func TestResolveNextDoH(t *testing.T) {
	oldDohServers := dohServers
	defer func() { dohServers = oldDohServers }()

	dohServers = []string{"https://doh1.example.com", "https://doh2.example.com"}

	s1 := resolveNextDoH()
	s2 := resolveNextDoH()
	s3 := resolveNextDoH()

	if s1 == "" || s2 == "" || s3 == "" {
		t.Error("Expected non-empty DoH servers")
	}

	if s1 == s2 {
		t.Errorf("Expected round-robin to return different servers, got %s twice", s1)
	}
	if s1 != s3 {
		t.Errorf("Expected round-robin to loop back, expected %s, got %s", s1, s3)
	}
}

func TestResolveNextPlain(t *testing.T) {
	oldPlainServers := plainServers
	defer func() { plainServers = oldPlainServers }()

	plainServers = []string{"192.0.2.1", "198.51.100.1"}

	s1 := resolveNextPlain()
	s2 := resolveNextPlain()
	s3 := resolveNextPlain()

	if s1 == "" || s2 == "" || s3 == "" {
		t.Error("Expected non-empty Plain servers")
	}

	if s1 == s2 {
		t.Errorf("Expected round-robin to return different servers, got %s twice", s1)
	}
	if s1 != s3 {
		t.Errorf("Expected round-robin to loop back, expected %s, got %s", s1, s3)
	}
}

func TestGetRandomUserAgent(t *testing.T) {
	oldUserAgents := userAgents
	defer func() { userAgents = oldUserAgents }()

	userAgents = []string{"Agent1", "Agent2"}

	s1 := GetRandomUserAgent()
	s2 := GetRandomUserAgent()
	s3 := GetRandomUserAgent()

	if s1 == "" || s2 == "" || s3 == "" {
		t.Error("Expected non-empty User-Agents")
	}

	if s1 == s2 {
		t.Errorf("Expected round-robin to return different agents, got %s twice", s1)
	}
	if s1 != s3 {
		t.Errorf("Expected round-robin to loop back, expected %s, got %s", s1, s3)
	}
}

func TestGetLastUsedDoH(t *testing.T) {
	lastUsedMu.Lock()
	lastUsedDoH = "https://doh.example.com"
	lastUsedMu.Unlock()

	if got := GetLastUsedDoH(); got != "https://doh.example.com" {
		t.Errorf("GetLastUsedDoH() = %v, want %v", got, "https://doh.example.com")
	}
}

func TestGetLastUsedPlain(t *testing.T) {
	lastUsedMu.Lock()
	lastUsedPlain = "203.0.113.1"
	lastUsedMu.Unlock()

	if got := GetLastUsedPlain(); got != "203.0.113.1" {
		t.Errorf("GetLastUsedPlain() = %v, want %v", got, "203.0.113.1")
	}
}

func TestGetDialer(t *testing.T) {
	dialer := GetDialer()
	if dialer == nil {
		t.Fatal("Expected GetDialer to return a non-nil dialer")
	}

	if dialer.Timeout != Timeout {
		t.Errorf("Expected Timeout %v, got %v", Timeout, dialer.Timeout)
	}

	if dialer.KeepAlive != KeepAlive {
		t.Errorf("Expected KeepAlive %v, got %v", KeepAlive, dialer.KeepAlive)
	}

	if dialer.Resolver == nil {
		t.Error("Expected Dialer.Resolver to be non-nil")
	}
}

func TestGetHTTPClient(t *testing.T) {
	t.Run("default transport clone", func(t *testing.T) {
		timeout := 45 * time.Second
		client := GetHTTPClient(timeout)
		if client == nil {
			t.Fatal("expected client, got nil")
		}
		if client.Timeout != timeout {
			t.Errorf("Expected Timeout %v, got %v", timeout, client.Timeout)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected Transport to be *http.Transport")
		}
		if tr.TLSHandshakeTimeout != 15*time.Second {
			t.Errorf("Expected TLSHandshakeTimeout 15s, got %v", tr.TLSHandshakeTimeout)
		}
	})

	t.Run("default transport fallback", func(t *testing.T) {
		orig := http.DefaultTransport
		defer func() { http.DefaultTransport = orig }()

		http.DefaultTransport = nil
		timeout := 45 * time.Second
		client := GetHTTPClient(timeout)
		if client == nil {
			t.Fatal("expected client, got nil")
		}
		if client.Timeout != timeout {
			t.Errorf("Expected Timeout %v, got %v", timeout, client.Timeout)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected Transport to be *http.Transport")
		}
		if tr.TLSHandshakeTimeout != 15*time.Second {
			t.Errorf("Expected TLSHandshakeTimeout 15s, got %v", tr.TLSHandshakeTimeout)
		}
		if !tr.ForceAttemptHTTP2 {
			t.Error("Expected ForceAttemptHTTP2 to be true")
		}
	})

	t.Run("tls timeout bounds", func(t *testing.T) {
		c1 := GetHTTPClient(15 * time.Second)
		tr1, ok := c1.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected Transport to be *http.Transport")
		}
		if tr1.TLSHandshakeTimeout != 10*time.Second {
			t.Errorf("Expected 10s bound, got %v", tr1.TLSHandshakeTimeout)
		}

		c2 := GetHTTPClient(90 * time.Second)
		tr2, ok := c2.Transport.(*http.Transport)
		if !ok {
			t.Fatal("expected Transport to be *http.Transport")
		}
		if tr2.TLSHandshakeTimeout != 20*time.Second {
			t.Errorf("Expected 20s bound, got %v", tr2.TLSHandshakeTimeout)
		}
	})
}

func TestDohStatusError_Error(t *testing.T) {
	err := &dohStatusError{code: 502}
	expected := "doh status 502"
	if err.Error() != expected {
		t.Errorf("Expected error string %q, got %q", expected, err.Error())
	}
}

type resolveDoHTest struct {
	name          string
	handler       http.HandlerFunc
	endpoint      string
	expectErrS    string
	expectIPs     []string
	qtype         int
	expectErr     bool
	useNilContext bool
}

func runResolveDoHSubtest(t *testing.T, tt resolveDoHTest) {
	var endpoint string
	if tt.handler != nil {
		ts := httptest.NewServer(tt.handler)
		defer ts.Close()
		endpoint = ts.URL
	} else {
		endpoint = tt.endpoint
	}

	ctx := context.Background()
	if tt.useNilContext {
		ctx = nil
	}

	ips, raw, err := resolveDoH(ctx, endpoint, "test.example.com", tt.qtype)

	if tt.expectErr {
		if err == nil {
			t.Fatalf("Expected error, got nil")
		}
		if tt.expectErrS != "" && !strings.Contains(err.Error(), tt.expectErrS) {
			t.Errorf("Expected error to contain %q, got %q", tt.expectErrS, err.Error())
		}
		return
	}

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(raw) == 0 {
		t.Error("Expected raw response, got empty")
	}
	if len(ips) != len(tt.expectIPs) {
		t.Fatalf("Expected %d IPs, got %d: %v", len(tt.expectIPs), len(ips), ips)
	}
	for i, ip := range ips {
		if ip != tt.expectIPs[i] {
			t.Errorf("Expected IP %d to be %q, got %q", i, tt.expectIPs[i], ip)
		}
	}
}

func TestResolveDoH(t *testing.T) {
	tests := []resolveDoHTest{
		{
			name:      "invalid endpoint url",
			endpoint:  "://invalid",
			expectErr: true,
		},
		{
			name: "http 500",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectErr:  true,
			expectErrS: "doh status 500",
		},
		{
			name: "invalid json",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte("{invalid-json}")); err != nil {
					return
				}
			},
			expectErr:  true,
			expectErrS: "unmarshal doh response",
		},
		{
			name: "dns status error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte(`{"Status": 2}`)); err != nil {
					return
				}
			},
			expectErr:  true,
			expectErrS: "dns status: 2",
		},
		{
			name: "read body error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusOK)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						if cerr := conn.Close(); cerr != nil {
							return
						}
					}
				}
			},
			expectErr:  true,
			expectErrS: "read body:",
		},
		{
			name:          "nil context",
			endpoint:      "http://192.0.2.3",
			expectErr:     true,
			expectErrS:    "net/http: nil Context",
			useNilContext: true,
		},
		{
			name:  "success",
			qtype: 1,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write([]byte(`{
					"Status": 0,
					"Answer": [
						{"name": "test.example.com", "type": 1, "data": "192.0.2.2", "TTL": 300},
						{"name": "test.example.com", "type": 28, "data": "2001:db8::1", "TTL": 300}
					],
					"Authority": [
						{"name": "test.example.com", "type": 1, "data": "198.51.100.1", "TTL": 300}
					]
				}`)); err != nil {
					return
				}
			},
			expectIPs: []string{"192.0.2.2", "198.51.100.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runResolveDoHSubtest(t, tt)
		})
	}
}

func TestResolveDoH_NetworkError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	ts.Close()

	_, _, err := resolveDoH(context.Background(), ts.URL, "test.example.com", 1)
	if err == nil {
		t.Fatal("Expected network error, got nil")
	}
}

type errorBody struct {
	io.Reader
}

func (errorBody) Close() error {
	return context.DeadlineExceeded
}

type mockTransport struct{}

func (mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       errorBody{strings.NewReader(`{"Status": 0}`)},
	}, nil
}

func TestResolveDoH_CloseError(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = mockTransport{}
	defer func() { http.DefaultTransport = oldTransport }()

	oldDebug := Options["Debug"]
	oldDebugConsole := Options["DebugConsole"]
	Options["Debug"] = strconv.FormatBool(true)
	Options["DebugConsole"] = strconv.FormatBool(true)
	defer func() {
		Options["Debug"] = oldDebug
		Options["DebugConsole"] = oldDebugConsole
	}()

	_, _, err := resolveDoH(context.Background(), "http://192.0.2.1", "test.example.com", 1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

type queryDoHDnsTest struct {
	name          string
	expectErrS    string
	servers       []string
	expectErr     bool
	useNilContext bool
}

func runQueryDoHDnsSubtest(t *testing.T, tt queryDoHDnsTest) {
	lastUsedMu.Lock()
	oldDoH := dohServers
	dohServers = tt.servers
	dohIndex.Store(^uint32(0))
	lastUsedMu.Unlock()

	defer func() {
		lastUsedMu.Lock()
		dohServers = oldDoH
		lastUsedMu.Unlock()
	}()

	ctx := context.Background()
	if tt.useNilContext {
		ctx = nil
	}

	resp, raw, err := QueryDoHDns(ctx, "test.example.com", 1)

	if tt.expectErr {
		if err == nil {
			t.Fatalf("Expected error, got nil")
		}
		if tt.expectErrS != "" && !strings.Contains(err.Error(), tt.expectErrS) {
			t.Errorf("Expected error %q, got %q", tt.expectErrS, err.Error())
		}
		return
	}

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp == nil || resp.Status != 0 {
		t.Errorf("Expected valid DoHResponse, got %v", resp)
	}
	if len(raw) == 0 {
		t.Error("Expected raw response")
	}
}

func TestQueryDoHDns(t *testing.T) {
	oldRetry := RetryBaseDelay
	RetryBaseDelay = time.Millisecond
	defer func() { RetryBaseDelay = oldRetry }()

	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts1.Close()

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts2.Close()

	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("{invalid json}")); err != nil {
			return
		}
	}))
	defer ts3.Close()

	ts4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"Status": 0, "Answer": [{"name": "test.example.com", "type": 1, "data": "192.0.2.3", "TTL": 300}]}`)); err != nil {
			return
		}
	}))
	defer ts4.Close()

	tsReadBodyErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				if cerr := conn.Close(); cerr != nil {
					return
				}
			}
		}
	}))
	defer tsReadBodyErr.Close()

	tsClosed := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	tsClosed.Close()

	tests := []queryDoHDnsTest{
		{
			name:    "success on first try",
			servers: []string{ts4.URL},
		},
		{
			name:       "failover network then 500 then 429 then invalid json then success",
			expectErrS: "",
			servers:    []string{tsClosed.URL, ts1.URL, ts2.URL, ts3.URL, tsReadBodyErr.URL, ts4.URL},
			expectErr:  false,
		},
		{
			name:       "all fail",
			servers:    []string{ts1.URL, ts2.URL},
			expectErr:  true,
			expectErrS: "all DoH attempts failed",
		},
		{
			name:       "invalid endpoint",
			servers:    []string{"://invalid"},
			expectErr:  true,
			expectErrS: "invalid endpoint url",
		},
		{
			name:          "nil context",
			servers:       []string{"http://192.0.2.3"},
			expectErr:     true,
			expectErrS:    "net/http: nil Context",
			useNilContext: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runQueryDoHDnsSubtest(t, tt)
		})
	}
}

func TestQueryDoHDns_CloseError(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = mockTransport{}
	defer func() { http.DefaultTransport = oldTransport }()

	oldDebug := Options["Debug"]
	oldDebugConsole := Options["DebugConsole"]
	Options["Debug"] = strconv.FormatBool(true)
	Options["DebugConsole"] = strconv.FormatBool(true)
	defer func() {
		Options["Debug"] = oldDebug
		Options["DebugConsole"] = oldDebugConsole
	}()

	lastUsedMu.Lock()
	oldDoH := dohServers
	dohServers = []string{"http://192.0.2.1"}
	dohIndex.Store(0)
	lastUsedMu.Unlock()
	defer func() {
		lastUsedMu.Lock()
		dohServers = oldDoH
		lastUsedMu.Unlock()
	}()

	_, _, err := QueryDoHDns(context.Background(), "test.example.com", 1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

type resolveRecordTest struct {
	plainFunc  func(context.Context, *net.Resolver) ([]string, error)
	name       string
	expectErrS string
	doh        []string
	expectRecs []string
	expectErr  bool
}

func runResolveRecordSubtest(t *testing.T, tt resolveRecordTest) {
	lastUsedMu.Lock()
	oldDoH := dohServers
	dohServers = tt.doh
	dohIndex.Store(^uint32(0))
	lastUsedMu.Unlock()
	defer func() {
		lastUsedMu.Lock()
		dohServers = oldDoH
		lastUsedMu.Unlock()
	}()

	recs, _, err := ResolveRecord(context.Background(), "test.example.com", 1, tt.plainFunc)
	if tt.expectErr {
		if err == nil {
			t.Fatalf("Expected error, got nil")
		}
		if tt.expectErrS != "" && !strings.Contains(err.Error(), tt.expectErrS) {
			t.Errorf("Expected error %q, got %q", tt.expectErrS, err.Error())
		}
		return
	}
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(tt.expectRecs) > 0 && (len(recs) == 0 || recs[0] != tt.expectRecs[0]) {
		t.Errorf("Unexpected records: %v", recs)
	}
}

func TestResolveRecord(t *testing.T) {
	oldRetry := RetryBaseDelay
	RetryBaseDelay = time.Millisecond
	defer func() { RetryBaseDelay = oldRetry }()

	tsSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"Status": 0, "Answer": [{"name": "test.example.com", "type": 1, "data": "192.0.2.3", "TTL": 300}]}`)); err != nil {
			return
		}
	}))
	defer tsSuccess.Close()

	tsAbort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tsAbort.Close()

	tsRateLimit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer tsRateLimit.Close()

	tests := []resolveRecordTest{
		{
			name:       "DoH success",
			doh:        []string{tsSuccess.URL},
			plainFunc:  nil,
			expectRecs: []string{"192.0.2.3"},
			expectErr:  false,
		},
		{
			name: "DoH abort fallback plain success",
			doh:  []string{tsAbort.URL},
			plainFunc: func(ctx context.Context, r *net.Resolver) ([]string, error) {
				if conn, err := r.Dial(ctx, "", ""); err == nil && conn != nil {
					if cerr := conn.Close(); cerr != nil {
						return nil, cerr
					}
				}
				return []string{"192.0.2.4"}, nil
			},
			expectErr: false,
		},
		{
			name: "DoH rate limit fallback plain nxdomain",
			doh:  []string{tsRateLimit.URL, tsRateLimit.URL, tsRateLimit.URL},
			plainFunc: func(_ context.Context, _ *net.Resolver) ([]string, error) {
				return nil, &net.DNSError{IsNotFound: true}
			},
			expectErr: false,
		},
		{
			name: "DoH fail fallback plain fail",
			doh:  []string{tsAbort.URL},
			plainFunc: func(ctx context.Context, r *net.Resolver) ([]string, error) {
				if conn, err := r.Dial(ctx, "", ""); err == nil && conn != nil {
					if cerr := conn.Close(); cerr != nil {
						return nil, cerr
					}
				}
				return nil, errors.New("plain error")
			},
			expectErr:  true,
			expectErrS: "all resolution attempts failed",
		},
		{
			name:       "DoH fail no fallback",
			doh:        []string{tsAbort.URL},
			plainFunc:  nil,
			expectErr:  true,
			expectErrS: "all DoH resolution attempts failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runResolveRecordSubtest(t, tt)
		})
	}
}

func TestResolveIP(t *testing.T) {
	oldRetry := RetryBaseDelay
	RetryBaseDelay = time.Millisecond
	defer func() { RetryBaseDelay = oldRetry }()

	tsSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"Status": 0, "Answer": [{"name": "test.example.com", "type": 1, "data": "192.0.2.3", "TTL": 300}]}`)); err != nil {
			return
		}
	}))
	defer tsSuccess.Close()

	tsAbort := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tsAbort.Close()

	tsSuccessAFailAAAA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := r.URL.Query().Get("type")
		if t == "28" {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if _, err := w.Write([]byte(`{"Status": 0, "Answer": [{"name": "test.example.com", "type": 1, "data": "192.0.2.3", "TTL": 300}]}`)); err != nil {
			return
		}
	}))
	defer tsSuccessAFailAAAA.Close()

	tests := []struct {
		name       string
		target     string
		expectErrS string
		doh        []string
		expectErr  bool
		canceled   bool
	}{
		{
			name:      "DoH success",
			doh:       []string{tsSuccess.URL},
			target:    "test.example.com",
			expectErr: false,
		},
		{
			name:      "Plain success localhost",
			doh:       []string{tsAbort.URL},
			target:    "localhost",
			expectErr: false,
		},
		{
			name:       "Plain nxdomain",
			doh:        []string{tsAbort.URL},
			target:     "nxdomain.example.com",
			expectErr:  true,
			expectErrS: "all resolution attempts failed",
		},
		{
			name:      "DoH partial success AAAA rate limit",
			target:    "test.example.com",
			doh:       []string{tsSuccessAFailAAAA.URL},
			expectErr: true,
		},
		{
			name:      "Plain network error",
			target:    "network-error.example.com",
			doh:       []string{tsAbort.URL},
			expectErr: true,
		},
		{
			name:      "Canceled context",
			target:    "example.com",
			doh:       []string{tsAbort.URL},
			expectErr: true,
			canceled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastUsedMu.Lock()
			oldDoH := dohServers
			oldPlain := plainServers
			dohServers = tt.doh
			dohIndex.Store(^uint32(0))
			plainIndex.Store(^uint32(0))
			if tt.name == "Plain network error" {
				plainServers = []string{"192.0.2.5"}
			} else {
				plainServers = []string{"127.0.0.1"}
			}
			lastUsedMu.Unlock()
			defer func() {
				lastUsedMu.Lock()
				dohServers = oldDoH
				plainServers = oldPlain
				lastUsedMu.Unlock()
			}()

			ctx := context.Background()
			if tt.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			_, _, err := ResolveIP(ctx, tt.target)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("Expected error, got nil")
				}
				if tt.expectErrS != "" && !strings.Contains(err.Error(), tt.expectErrS) {
					t.Errorf("Expected error %q, got %q", tt.expectErrS, err.Error())
				}
				return
			}
			if err != nil && !strings.Contains(err.Error(), "nxdomain") {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGetResolver(t *testing.T) {
	lastUsedMu.Lock()
	oldPlain := plainServers
	plainServers = []string{"198.51.100.123"}
	plainIndex.Store(^uint32(0))
	lastUsedMu.Unlock()

	defer func() {
		lastUsedMu.Lock()
		plainServers = oldPlain
		lastUsedMu.Unlock()
	}()

	r := GetResolver()
	if r == nil || r.Dial == nil {
		t.Fatalf("GetResolver returned invalid resolver")
	}

	if conn, err := r.Dial(context.Background(), "", ""); err == nil && conn != nil {
		if cerr := conn.Close(); cerr != nil {
			t.Logf("close err: %v", cerr)
		}
	}
}
