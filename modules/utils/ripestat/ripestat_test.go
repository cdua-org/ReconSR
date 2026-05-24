package ripestat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
)

// writeTestResponse writes data to the ResponseWriter and reports
// a test error if the write fails. Safe from handler goroutines.
func writeTestResponse(t *testing.T, w http.ResponseWriter, data string) {
	t.Helper()
	if _, err := w.Write([]byte(data)); err != nil {
		t.Errorf("failed to write test response: %v", err)
	}
}

// withMockHost temporarily replaces the package-level host variable
// with the given URL and restores it when the returned function is called.
func withMockHost(t *testing.T, url string) func() {
	t.Helper()
	original := host
	host = url
	return func() { host = original }
}

// withFastRetries temporarily reduces retry delays for test speed.
func withFastRetries(t *testing.T) func() {
	t.Helper()
	origDelay := resolver.RetryBaseDelay
	origTimeout := resolver.Timeout
	origHTTPTimeout := resolver.HTTPTimeout
	resolver.RetryBaseDelay = 10 * time.Millisecond
	resolver.Timeout = 2 * time.Second
	resolver.HTTPTimeout = 2 * time.Second
	return func() {
		resolver.RetryBaseDelay = origDelay
		resolver.Timeout = origTimeout
		resolver.HTTPTimeout = origHTTPTimeout
	}
}

func TestAttemptQuery_Success_ASOverview(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"holder":"RIPE NCC"}}`)
	}))
	defer srv.Close()

	var resp ASOverviewResponse
	err := attemptQuery(context.Background(), srv.URL, "AS3333", "as-overview", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data.Holder != "RIPE NCC" {
		t.Errorf("holder = %q, want %q", resp.Data.Holder, "RIPE NCC")
	}
}

func TestAttemptQuery_Success_AbuseContacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"abuse_contacts":["abuse@example.com","noc@example.com"]}}`)
	}))
	defer srv.Close()

	var resp AbuseContactResponse
	err := attemptQuery(context.Background(), srv.URL, "8.8.8.8", "abuse-contact-finder", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Data.AbuseContacts) != 2 {
		t.Fatalf("contacts count = %d, want 2", len(resp.Data.AbuseContacts))
	}
	if resp.Data.AbuseContacts[0] != "abuse@example.com" {
		t.Errorf("contact[0] = %q, want %q", resp.Data.AbuseContacts[0], "abuse@example.com")
	}
}

func TestAttemptQuery_Success_Neighbours(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"neighbours":[{"type":"left","asn":1299,"power":50,"v4_peers":10}]}}`)
	}))
	defer srv.Close()

	var resp APIResponse
	err := attemptQuery(context.Background(), srv.URL, "AS3333", "asn-neighbours", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Data.Neighbours) != 1 {
		t.Fatalf("neighbours count = %d, want 1", len(resp.Data.Neighbours))
	}
	n := resp.Data.Neighbours[0]
	if n.ASN != 1299 {
		t.Errorf("ASN = %d, want 1299", n.ASN)
	}
	if n.Position != "left" {
		t.Errorf("Position = %q, want %q", n.Position, "left")
	}
}

func TestAttemptQuery_Success_AnnouncedPrefixes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"prefixes":[{"prefix":"193.0.0.0/21"},{"prefix":"2001:67c:2e8::/48"}]}}`)
	}))
	defer srv.Close()

	var resp AnnouncedPrefixesResponse
	err := attemptQuery(context.Background(), srv.URL, "AS3333", "announced-prefixes", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Data.Prefixes) != 2 {
		t.Fatalf("prefixes count = %d, want 2", len(resp.Data.Prefixes))
	}
	if resp.Data.Prefixes[0].Prefix != "193.0.0.0/21" {
		t.Errorf("prefix[0] = %q, want %q", resp.Data.Prefixes[0].Prefix, "193.0.0.0/21")
	}
}

func TestAttemptQuery_Success_Whois(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"records":[[{"key":"netname","value":"APNIC-LABS"}]]}}`)
	}))
	defer srv.Close()

	var resp WhoisResponse
	err := attemptQuery(context.Background(), srv.URL, "1.1.1.1", "whois", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Data.Records) != 1 {
		t.Fatalf("records count = %d, want 1", len(resp.Data.Records))
	}
	if resp.Data.Records[0][0].Key != "netname" {
		t.Errorf("key = %q, want %q", resp.Data.Records[0][0].Key, "netname")
	}
}

func TestAttemptQuery_RawJSON_Populated(t *testing.T) {
	payload := `{"data":{"holder":"Test Org"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, payload)
	}))
	defer srv.Close()

	var resp ASOverviewResponse
	if err := attemptQuery(context.Background(), srv.URL, "AS1", "as-overview", &resp, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RawJSON != payload {
		t.Errorf("RawJSON = %q, want %q", resp.RawJSON, payload)
	}
}

func TestAttemptQuery_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var resp ASOverviewResponse
	err := attemptQuery(context.Background(), srv.URL, "AS1", "as-overview", &resp, 1)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
	if !strings.Contains(err.Error(), "http status 500") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "http status 500")
	}
}

func TestAttemptQuery_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{invalid json`)
	}))
	defer srv.Close()

	var resp ASOverviewResponse
	err := attemptQuery(context.Background(), srv.URL, "AS1", "as-overview", &resp, 1)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "unmarshal")
	}
}

func TestAttemptQuery_ContextCancelled(t *testing.T) {
	defer withFastRetries(t)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var resp ASOverviewResponse
	err := attemptQuery(ctx, srv.URL, "AS1", "as-overview", &resp, 1)
	if err == nil {
		t.Fatal("expected context deadline error")
	}
}

func TestQuery_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/data/as-overview/data.json") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("resource") != "AS3333" {
			t.Errorf("resource = %q, want %q", r.URL.Query().Get("resource"), "AS3333")
		}
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"holder":"RIPE NCC"}}`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	var resp ASOverviewResponse
	err := Query(context.Background(), "AS3333", "as-overview", &resp, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data.Holder != "RIPE NCC" {
		t.Errorf("holder = %q, want %q", resp.Data.Holder, "RIPE NCC")
	}
}

func TestQuery_RetryOnServerError(t *testing.T) {
	defer withFastRetries(t)()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		writeTestResponse(t, w, `{"data":{"holder":"OK"}}`)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	var resp ASOverviewResponse
	err := Query(context.Background(), "AS1", "as-overview", &resp, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Data.Holder != "OK" {
		t.Errorf("holder = %q, want %q", resp.Data.Holder, "OK")
	}
	if c := calls.Load(); c != 3 {
		t.Errorf("calls = %d, want 3", c)
	}
}

func TestQuery_AllAttemptsFail(t *testing.T) {
	defer withFastRetries(t)()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	var resp ASOverviewResponse
	err := Query(context.Background(), "AS1", "as-overview", &resp, 3)
	if err == nil {
		t.Fatal("expected error when all attempts fail")
	}
	if !strings.Contains(err.Error(), "all attempts failed") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "all attempts failed")
	}
	if c := calls.Load(); c != 3 {
		t.Errorf("calls = %d, want 3 (should exhaust all retries)", c)
	}
}

func TestQuery_ContextCancelled_StopsRetries(t *testing.T) {
	defer withFastRetries(t)()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	var resp ASOverviewResponse
	err := Query(ctx, "AS1", "as-overview", &resp, 10)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if c := calls.Load(); c >= 10 {
		t.Errorf("calls = %d, expected fewer than 10 (context should cancel retries)", c)
	}
}

func TestQuery_SingleAttempt_NoRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	defer withMockHost(t, srv.URL)()

	var resp ASOverviewResponse
	err := Query(context.Background(), "AS1", "as-overview", &resp, 1)
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if c := calls.Load(); c != 1 {
		t.Errorf("calls = %d, want 1 (maxRetries=1 means single attempt)", c)
	}
}

func TestModels_SetRawJSON(t *testing.T) {
	const rawJSON = `{"test":"data"}`

	tests := []struct {
		target rawResponse
		name   string
	}{
		{&APIResponse{}, "APIResponse"},
		{&AnnouncedPrefixesResponse{}, "AnnouncedPrefixesResponse"},
		{&ASOverviewResponse{}, "ASOverviewResponse"},
		{&AbuseContactResponse{}, "AbuseContactResponse"},
		{&WhoisResponse{}, "WhoisResponse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.target.setRawJSON(rawJSON)

			switch v := tt.target.(type) {
			case *APIResponse:
				if v.RawJSON != rawJSON {
					t.Errorf("RawJSON = %q", v.RawJSON)
				}
			case *AnnouncedPrefixesResponse:
				if v.RawJSON != rawJSON {
					t.Errorf("RawJSON = %q", v.RawJSON)
				}
			case *ASOverviewResponse:
				if v.RawJSON != rawJSON {
					t.Errorf("RawJSON = %q", v.RawJSON)
				}
			case *AbuseContactResponse:
				if v.RawJSON != rawJSON {
					t.Errorf("RawJSON = %q", v.RawJSON)
				}
			case *WhoisResponse:
				if v.RawJSON != rawJSON {
					t.Errorf("RawJSON = %q", v.RawJSON)
				}
			}
		})
	}
}
