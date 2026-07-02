package whois

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
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

	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	ianaRDAPBootstrap.Do(func() {})
	originalServers := make(map[string]string)
	if ianaRDAPServers == nil {
		ianaRDAPServers = make(map[string]string)
	}
	maps.Copy(originalServers, ianaRDAPServers)
	ianaRDAPServers["example"] = "http://127.0.0.1:0/"

	origIana := ianaWhoisServer
	ianaWhoisServer = "127.0.0.1"

	origDial := dialContextFunc
	dialContextFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("mocked dial")
	}

	origRDAP := rdapClientDo
	rdapClientDo = func(_ *http.Client, _ *http.Request) (*http.Response, error) {
		return nil, errors.New("mocked rdap")
	}

	defer func() {
		ianaWhoisServer = origIana
		dialContextFunc = origDial
		rdapClientDo = origRDAP
		for k := range ianaRDAPServers {
			delete(ianaRDAPServers, k)
		}
		maps.Copy(ianaRDAPServers, originalServers)
	}()

	res, err := m.Exec(schema.ModuleInput{
		Functions: []string{constants.FuncGetWhois, "unknown_func"},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "rdap.example",
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

func TestGetWhoisData(t *testing.T) {
	origDelay := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = origDelay }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail.example") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"test": "` + strings.Repeat("A", 300) + `"}`)); err != nil {
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
	ianaRDAPServers["example"] = ts.URL + "/"
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

	exec1 := m.getWhoisData("rdap.example")
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

	exec2 := m.getWhoisData("fail.example")
	if exec2.Error != nil {
		t.Errorf("unexpected error on fallback: %v", *exec2.Error)
	}
	if exec2.RawData == "" {
		t.Errorf("expected RawData for WHOIS fallback")
	}

	execLong := m.getWhoisData("long.example")
	if execLong.Error != nil {
		t.Errorf("unexpected error on long: %v", *execLong.Error)
	}

	resolver.Options["DisableRDAP"] = "true"
	defer delete(resolver.Options, "DisableRDAP")
	exec3 := m.getWhoisData("bad.example")
	if exec3.Error == nil {
		t.Errorf("expected error when both fail")
	}
}
