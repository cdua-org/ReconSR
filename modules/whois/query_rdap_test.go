package whois

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

func mockRDAPHandler(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "rdap.example") {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"test": "rdap_success"}`)); err != nil {
			panic(err)
		}
		return
	}
	if strings.Contains(r.URL.Path, "fail.example") {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if strings.Contains(r.URL.Path, "notfound.example") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.Contains(r.URL.Path, "badjson.example") {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{invalid_json`)); err != nil {
			panic(err)
		}
		return
	}
	if strings.Contains(r.URL.Path, "rate.example") {
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
	ianaRDAPServers["example"] = ts.URL + "/"

	ctx := context.Background()
	data, err := queryRDAP(ctx, "rdap.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if data["test"] != "rdap_success" {
		t.Errorf("unexpected data: %v", data)
	}

	_, err = queryRDAP(ctx, "fail.example")
	if err == nil {
		t.Error("expected error for fail.example")
	}

	_, err = queryRDAP(ctx, "notfound.example")
	if err == nil {
		t.Error("expected error for notfound.example")
	}

	_, err = queryRDAP(ctx, "badjson.example")
	if err == nil {
		t.Error("expected error for badjson.example")
	}
	_, err = queryRDAP(ctx, "unreachable.example")
	if err == nil {
		t.Error("expected error for unreachable.example")
	}

	ianaRDAPServers["example"] = "http://127.0.0.1:0/\x7f"
	_, err = queryRDAP(ctx, "badurl.example")
	if err == nil {
		t.Error("expected error for bad url")
	}

	oldRdapClientDo := rdapClientDo
	rdapClientDo = func(_ *http.Client, _ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errCloser{strings.NewReader(`{"test":"rdap_success"}`)},
		}, nil
	}
	defer func() { rdapClientDo = oldRdapClientDo }()

	ianaRDAPServers["example"] = "http://127.0.0.1:0/"
	_, err = queryRDAP(ctx, "closeerr.example")
	if err != nil {
		t.Errorf("unexpected error on closeerr: %v", err)
	}
	rdapClientDo = oldRdapClientDo

	ianaRDAPServers["example"] = "http://127.0.0.1:1/"
	_, err = queryRDAP(ctx, "dead.example")
	if err == nil {
		t.Error("expected error for dead url")
	}

	ianaRDAPServers["example"] = ts.URL + "/rate.example/"
	origDelayRate := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = 100 * time.Millisecond
	ctxCancel, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err = queryRDAP(ctxCancel, "ratelimit.example")
	if err == nil {
		t.Error("expected error for sleep context")
	}
	resolver.RetryBaseDelay = origDelayRate
}

type errCloser struct {
	io.Reader
}

func (errCloser) Close() error {
	return errors.New("close error")
}
