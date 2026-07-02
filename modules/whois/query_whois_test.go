package whois

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestFormatWHOISQuery(t *testing.T) {
	tests := []struct {
		server   string
		query    string
		expected string
	}{
		{"whois.jprs.jp", "example.jp", "example.jp/e"},
		{"whois.jprs.jp", "example2.jp/e", "example2.jp/e"},
		{"whois.verisign-grs.com", "example.net", "=example.net"},
		{"whois.denic.de", "example.de", "-T dn example.de"},
		{"whois.iana.org", "example.org", "example.org"},
		{"whois.test.example", "lookup.test.example.net", "lookup.test.example.net"},
		{"whois.mock.example", "query.mock.example.org", "query.mock.example.org"},
		{"whois.nic.name", "example.name", "domain=example.name"},
	}

	for _, tc := range tests {
		if got := formatWHOISQuery(tc.server, tc.query); got != tc.expected {
			t.Errorf("formatWHOISQuery(%q, %q) = %q, want %q", tc.server, tc.query, got, tc.expected)
		}
	}
}

type mockNetConn struct {
	failClose       bool
	failSetDeadline bool
	failWrite       bool
	failRead        bool
}

func (m mockNetConn) Read(_ []byte) (n int, err error) {
	if m.failRead {
		return 0, errors.New("read error")
	}
	return 0, io.EOF
}
func (m mockNetConn) Write(b []byte) (n int, err error) {
	if m.failWrite {
		return 0, errors.New("write error")
	}
	return len(b), nil
}
func (m mockNetConn) Close() error {
	if m.failClose {
		return errors.New("close error")
	}
	return nil
}
func (m mockNetConn) LocalAddr() net.Addr  { return nil }
func (m mockNetConn) RemoteAddr() net.Addr { return nil }
func (m mockNetConn) SetDeadline(_ time.Time) error {
	if m.failSetDeadline {
		return errors.New("set deadline error")
	}
	return nil
}
func (m mockNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m mockNetConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestDialWHOISErrors(t *testing.T) {
	origDial := dialContextFunc
	origRetries := resolver.MaxRetriesWhois
	resolver.MaxRetriesWhois = 1
	defer func() {
		dialContextFunc = origDial
		resolver.MaxRetriesWhois = origRetries
	}()

	dialContextFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		return mockNetConn{failSetDeadline: true}, nil
	}
	_, err := dialWHOIS(context.Background(), "mock.example", "example.com")
	if err == nil || !strings.Contains(err.Error(), "set deadline error") {
		t.Errorf("expected set deadline error, got %v", err)
	}

	dialContextFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		return mockNetConn{failWrite: true}, nil
	}
	_, err = dialWHOIS(context.Background(), "mock.example", "example.com")
	if err == nil || !strings.Contains(err.Error(), "write error") {
		t.Errorf("expected write error, got %v", err)
	}

	dialContextFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		return mockNetConn{failClose: true}, nil
	}
	_, err = dialWHOIS(context.Background(), "mock.example", "example.com")
	if err != nil {
		t.Logf("dialWHOIS returned error on failClose (expected or not): %v", err)
	}
}

func handleMockWHOISConn(c net.Conn, host string) {
	defer func() {
		if cerr := c.Close(); cerr != nil && !strings.Contains(cerr.Error(), "use of closed network connection") {
			panic(cerr)
		}
	}()
	if sErr := c.SetDeadline(time.Now().Add(1 * time.Second)); sErr != nil {
		return
	}
	buf := make([]byte, 1024)
	n, readErr := c.Read(buf)
	if readErr != nil {
		return
	}
	req := string(buf[:n])
	writeMockWHOISResponse(c, req, host)
}

func writeMockWHOISResponse(c net.Conn, req, _ string) {
	switch {
	case strings.Contains(req, "refer.example"):
		if _, err := c.Write([]byte("refer: localhost\nwhois: refer.example\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "example.refer"):
		if _, err := c.Write([]byte("refer server response")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "dialfail.example"):
		if _, err := c.Write([]byte("Identity Digital Inc.\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "bad.example"):
		if _, err := c.Write([]byte("refer: 256.256.256.256\nwhois: bad.example\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "timeout.example"):
		time.Sleep(100 * time.Millisecond)
	case strings.Contains(req, "long.example"):
		if _, err := c.Write([]byte(strings.Repeat("A", 400))); err != nil {
			panic(err)
		}
	default:
		if _, err := c.Write([]byte("default response")); err != nil {
			panic(err)
		}
	}
}

func startMockWHOIS(t *testing.T) (mockHost, mockPort string, mockListener net.Listener) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	host, port, splitErr := net.SplitHostPort(l.Addr().String())
	if splitErr != nil {
		t.Fatalf("failed to split host port: %v", splitErr)
	}

	go func() {
		defer func() {
			if cerr := l.Close(); cerr != nil && !strings.Contains(cerr.Error(), "use of closed network connection") {
				panic(cerr)
			}
		}()
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			go handleMockWHOISConn(conn, host)
		}
	}()

	return host, port, l
}

func TestQueryWHOIS_Basic(t *testing.T) {
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	host, port, l := startMockWHOIS(t)
	defer func() {
		if cerr := l.Close(); cerr != nil {
			panic(cerr)
		}
	}()

	originalIana := ianaWhoisServer
	originalPort := whoisPort
	ianaWhoisServer = host
	whoisPort = port
	defer func() {
		ianaWhoisServer = originalIana
		whoisPort = originalPort
	}()

	ctx := context.Background()

	res, err := queryWHOIS(ctx, "basic.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(res, "default response") {
		t.Errorf("unexpected res: %s", res)
	}

	res, err = queryWHOIS(ctx, "refer.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("REFER RES: %q\n", res)
	if !strings.Contains(res, "refer: ") {
		t.Errorf("unexpected res: %s", res)
	}

	ianaWhoisServer = "256.256.256.256"
	_, err = queryWHOIS(ctx, "whoisfail.example")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	ianaWhoisServer = host

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := queryWHOIS(ctxTimeout, "timeout.example"); err == nil {
		t.Errorf("expected timeout error")
	}
}

func TestQueryWHOIS_Refer(t *testing.T) {
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	host, port, l := startMockWHOIS(t)
	defer func() {
		if cerr := l.Close(); cerr != nil {
			panic(cerr)
		}
	}()

	originalIana := ianaWhoisServer
	originalPort := whoisPort
	ianaWhoisServer = host
	whoisPort = port
	defer func() {
		ianaWhoisServer = originalIana
		whoisPort = originalPort
	}()

	ctx := context.Background()

	res, err := queryWHOIS(ctx, "refer.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(res, "refer: ") {
		t.Errorf("unexpected res: %s", res)
	}

	resBad, err := queryWHOIS(ctx, "bad.example")
	if err == nil {
		t.Errorf("expected error for bad refer, got: %s", resBad)
	}

	ianaWhoisServer = host
	ctxFast, cancelFast := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelFast()
	if _, err := queryWHOIS(ctxFast, "dialfail.example"); err == nil {
		t.Errorf("expected dial error")
	}
}
