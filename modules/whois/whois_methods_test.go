package whois

import (
	"context"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestModuleInfo(t *testing.T) {
	m := New()
	if m.Name() != "whois" {
		t.Errorf("expected whois, got %s", m.Name())
	}
	_, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := m.Exec(schema.ModuleInput{
		Functions: []string{constants.FuncGetWhois, "unknown_func"},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "example.mocktld",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Executions) != 2 {
		t.Errorf("expected 2 executions, got %d", len(res.Executions))
	}
	if res.Executions[1].Error == nil {
		t.Errorf("expected error for unknown_func")
	}
}

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

func mockRDAPHandler(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "example.mocktld") {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"test": "rdap_success"}`)); err != nil {
			panic(err)
		}
		return
	}
	if strings.Contains(r.URL.Path, "fail.mocktld") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if strings.Contains(r.URL.Path, "notfound.mocktld") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.Contains(r.URL.Path, "badjson.mocktld") {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{invalid_json`)); err != nil {
			panic(err)
		}
		return
	}
	if strings.Contains(r.URL.Path, "rate.mocktld") {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
}

func TestQueryRDAP(t *testing.T) {
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	ts := httptest.NewServer(http.HandlerFunc(mockRDAPHandler))
	defer ts.Close()

	ianaRDAPBootstrap.Do(func() {})
	if ianaRDAPServers == nil {
		ianaRDAPServers = make(map[string]string)
	}
	ianaRDAPServers["mocktld"] = ts.URL + "/"

	ctx := context.Background()
	data, err := queryRDAP(ctx, "example.mocktld")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if data["test"] != "rdap_success" {
		t.Errorf("unexpected data: %v", data)
	}

	_, err = queryRDAP(ctx, "fail.mocktld")
	if err == nil {
		t.Error("expected error for fail.mocktld")
	}

	_, err = queryRDAP(ctx, "notfound.mocktld")
	if err == nil {
		t.Error("expected error for notfound.mocktld")
	}

	_, err = queryRDAP(ctx, "badjson.mocktld")
	if err == nil {
		t.Error("expected error for badjson.mocktld")
	}
	_, err = queryRDAP(ctx, "unreachable.mocktld")
	if err == nil {
		t.Error("expected error for unreachable.mocktld")
	}

	ianaRDAPServers["badurl"] = "http://127.0.0.1:0/\x7f"
	_, err = queryRDAP(ctx, "domain.badurl")
	if err == nil {
		t.Error("expected error for bad url")
	}

	ianaRDAPServers["dead"] = "http://127.0.0.1:1/"
	_, err = queryRDAP(ctx, "domain.dead")
	if err == nil {
		t.Error("expected error for dead url")
	}

	ianaRDAPServers["rate"] = ts.URL + "/rate.mocktld/"
	origDelayRate := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 100 * time.Millisecond
	ctxCancel, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = queryRDAP(ctxCancel, "domain.rate")
	if err == nil {
		t.Error("expected error for sleep context")
	}
	resolver.RetryBaseDelay = origDelayRate
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
	case strings.Contains(req, "example.iana"):
		if _, err := c.Write([]byte("refer: localhost\nwhois: example.iana\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "example.refer"):
		if _, err := c.Write([]byte("refer server response")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "identity.digital"):
		if _, err := c.Write([]byte("Identity Digital Inc.\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "badrefer.iana"):
		if _, err := c.Write([]byte("refer: 256.256.256.256\nwhois: badrefer.iana\n")); err != nil {
			panic(err)
		}
	case strings.Contains(req, "example.timeout"):
		time.Sleep(100 * time.Millisecond)
	case strings.Contains(req, "example.long"):
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

	res, err := queryWHOIS(ctx, "example.mock")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(res, "default response") {
		t.Errorf("unexpected res: %s", res)
	}

	res, err = queryWHOIS(ctx, "example.iana")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	t.Logf("REFER RES: %q\n", res)
	if !strings.Contains(res, "refer: ") {
		t.Errorf("unexpected res: %s", res)
	}

	ianaWhoisServer = "256.256.256.256"
	_, err = queryWHOIS(ctx, "fail.mock")
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	ianaWhoisServer = host

	ctxTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := queryWHOIS(ctxTimeout, "example.timeout"); err == nil {
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

	res, err := queryWHOIS(ctx, "example.iana")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(res, "refer: ") {
		t.Errorf("unexpected res: %s", res)
	}

	_, err = queryWHOIS(ctx, "badrefer.iana")
	if err == nil {
		t.Errorf("expected error for bad refer")
	}

	ianaWhoisServer = host
	ctxFast, cancelFast := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelFast()
	if _, err := queryWHOIS(ctxFast, "identity.digital"); err == nil {
		t.Errorf("expected dial error")
	}
}

func TestGetWhoisData(t *testing.T) {
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail.mocktld") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"test": "success"}`)); err != nil {
			panic(err)
		}
	}))
	defer ts.Close()

	ianaRDAPBootstrap.Do(func() {})
	if ianaRDAPServers == nil {
		ianaRDAPServers = make(map[string]string)
	}
	originalServers := make(map[string]string)
	maps.Copy(originalServers, ianaRDAPServers)
	ianaRDAPServers["mocktld"] = ts.URL + "/"
	defer func() {
		for k := range ianaRDAPServers {
			delete(ianaRDAPServers, k)
		}
		maps.Copy(ianaRDAPServers, originalServers)
	}()

	m, ok := New().(*module)
	if !ok {
		t.Fatalf("New() did not return *module")
	}

	exec1 := m.getWhoisData("example.mocktld")
	if exec1.Error != nil {
		t.Errorf("unexpected error: %v", *exec1.Error)
	}

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

	exec2 := m.getWhoisData("fail.mocktld")
	if exec2.Error != nil {
		t.Errorf("unexpected error on fallback: %v", *exec2.Error)
	}
	if exec2.RawData == "" {
		t.Errorf("expected RawData for WHOIS fallback")
	}

	execLong := m.getWhoisData("example.long")
	if execLong.Error != nil {
		t.Errorf("unexpected error on long: %v", *execLong.Error)
	}

	resolver.Options["DisableRDAP"] = "true"
	defer delete(resolver.Options, "DisableRDAP")
	exec3 := m.getWhoisData("badrefer.iana")
	if exec3.Error == nil {
		t.Errorf("expected error when both fail")
	}
}

func TestAppendHelpers(t *testing.T) {
	m, ok := New().(*module)
	if !ok {
		t.Fatalf("New() did not return *module")
	}
	gen := modutil.NewLocalIDGenerator()
	var results []schema.ModuleResult

	m.appendSlice(&results, []string{"val1", "val2"}, constants.TypeStatus, "ctx", false, nil, "", gen)
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	m.appendSlice(&results, []string{"", "  ", "valid@example.net", "invalid-email"}, constants.TypeEmail, "ctx", false, nil, "", gen)
	m.appendSlice(&results, []string{"Bob"}, constants.TypePerson, "ctx", false, nil, "", gen)
	m.appendSlice(&results, []string{"Org"}, constants.TypeOrganization, "ctx", false, nil, "", gen)

	m.appendAddress(&results, []string{"", "  ", "123", "456"}, "address", "Registrant", false, nil, "ctx", gen)
	m.appendAddress(&results, []string{"", "  "}, "address", "Registrant", false, nil, "ctx", gen)

	contact := Contact{
		Name:         []string{"Bob"},
		Organization: []string{"PrivacyProtect"},
		Email:        []string{"bob@example.com"},
		Phone:        []string{"555-1234", "+", "+1-555-123-4567"},
		Fax:          []string{"555-4321"},
		Address:      []string{"123 Street"},
	}
	m.appendContact(&results, &contact, "Registrant", "contactRole", false, nil, "ctx", "target", gen)

	contactEmpty := Contact{}
	m.appendContact(&results, &contactEmpty, "Registrant", "", false, nil, "ctx", "target", gen)

	meta := &Metadata{
		RegistrarURL:   "http://reg.example.com",
		WhoisServer:    "whois.reg.example.com",
		IANAID:         "123",
		DNSSEC:         "unsigned",
		CreationDate:   "2020-01-01",
		UpdatedDate:    "2021-01-01",
		ExpirationDate: "2022-01-01",
		DomainStatus:   []string{"clientUpdateProhibited"},
		NameServers:    []string{"ns1.fallback.example.net", "ns1", "ns3.invalid_domain!!!"},
		Registrar: Contact{
			Name: []string{"Reg"},
		},
	}
	anchor, anchorRes := m.getRegistrarAnchor(meta, "target", "ctx", gen)
	metaRes := m.buildMetadataResults(meta, "target", "ctx", anchor, gen)

	finalResults := make([]schema.ModuleResult, 0, len(results)+len(anchorRes)+len(metaRes))
	finalResults = append(finalResults, results...)
	finalResults = append(finalResults, anchorRes...)
	finalResults = append(finalResults, metaRes...)
	_ = finalResults
}

func TestBuildWhoisServerResult(t *testing.T) {
	res, ok := buildWhoisServerResult("whois.example.com", "example.com")
	if !ok || res.Value != "whois.example.com" {
		t.Errorf("unexpected result: %+v", res)
	}

	_, ok = buildWhoisServerResult("invalid_domain", "ctx")
	if ok {
		t.Errorf("expected failure for invalid domain, got ok")
	}
}
