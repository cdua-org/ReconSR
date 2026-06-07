package shodan

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestSanitizeShodanErrorNilAndPassThrough(t *testing.T) {
	if sanitizeShodanError(nil) != nil {
		t.Fatal("expected nil error to stay nil")
	}

	plainErr := errors.New("plain failure")
	if !errors.Is(sanitizeShodanError(plainErr), plainErr) {
		t.Fatal("expected unchanged error to be returned as-is")
	}
}

func TestHandlePreflightAPIErrorBranches(t *testing.T) {
	t.Run("create_request_error", func(t *testing.T) {
		withShodanBaseURL(t, "://bad")

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after request creation error")
		}
	})

	t.Run("do_request_error", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("Get %q: EOF", req.URL.String())
		}))

		module := &shodanModule{apiKey: "secret-key"}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after transport error")
		}
	})

	t.Run("forbidden_status", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusForbidden, `{}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after forbidden response")
		}
	})

	t.Run("unexpected_status", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusInternalServerError, `{}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after unexpected status")
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return okBodyResponse(failingReadCloser{
				readErr:  errors.New("broken body"),
				closeErr: errors.New("broken close"),
			}), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after body read error")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusOK, `{"query_credits":`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		module.handlePreflightAPI()
		if !module.keyInvalid {
			t.Fatal("expected invalid key state after invalid json")
		}
	})
}

func TestGetShodanAPIIPBranches(t *testing.T) {
	target := schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()}

	t.Run("invalid_key_short_circuit", func(t *testing.T) {
		module := &shodanModule{apiKey: shodanTestAPIKey(), keyInvalid: true}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		info := requireModuleResult(t, exec.Results, constants.TypeInfo, "Shodan API key is invalid")
		if info.Category != constants.CategoryProperty {
			t.Fatalf("expected info property, got %+v", info)
		}
	})

	t.Run("parse_url_error", func(t *testing.T) {
		withShodanBaseURL(t, "://bad")

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "parse url") {
			t.Fatalf("expected parse url error, got %+v", exec.Error)
		}
	})

	t.Run("do_request_error_is_sanitized", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("Get %q: EOF", req.URL.String())
		}))

		module := &shodanModule{apiKey: "very-secret-key"}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error == nil {
			t.Fatal("expected request error")
		}
		if strings.Contains(*exec.Error, "very-secret-key") {
			t.Fatalf("expected api key to be redacted, got %q", *exec.Error)
		}
		if !strings.Contains(*exec.Error, "key=[redacted]") {
			t.Fatalf("expected redacted marker, got %q", *exec.Error)
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return okBodyResponse(failingReadCloser{
				readErr:  errors.New("ip body failed"),
				closeErr: errors.New("ip close failed"),
			}), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "read body") {
			t.Fatalf("expected read body error, got %+v", exec.Error)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusNotFound, `{"detail":"no data"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error != nil {
			t.Fatalf("expected no error for not found, got %v", *exec.Error)
		}
		if exec.RawData == "" {
			t.Fatal("expected raw data for not found response")
		}
	})

	t.Run("rate_limit", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusTooManyRequests, `{"error":"slow down"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "HTTP 429 Rate Limit") {
			t.Fatalf("expected 429 error, got %+v", exec.Error)
		}
	})

	t.Run("unexpected_http_status", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusBadGateway, `{"error":"bad gateway"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey()}
		markPreflightDone(module)

		exec := module.getShodanAPIIP(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "http status") {
			t.Fatalf("expected http status error, got %+v", exec.Error)
		}
	})
}

func TestDoDomainPageRequestParseURLError(t *testing.T) {
	withShodanBaseURL(t, "://bad")

	module := &shodanModule{apiKey: shodanTestAPIKey()}
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}

	body, status, ok := module.doDomainPageRequest("pr.example.com", 1, &exec)
	if ok || body != nil || status != 0 {
		t.Fatalf("expected request creation to fail, got ok=%v status=%d body=%q", ok, status, string(body))
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "parse url") {
		t.Fatalf("expected parse url error, got %+v", exec.Error)
	}
}

func TestDoDomainPageRequestRequestErrorIsSanitized(t *testing.T) {
	withShodanBaseURL(t, "http://shodan.test")
	withDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("Get %q: EOF", req.URL.String())
	}))

	module := &shodanModule{apiKey: "very-secret-key"}
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}

	body, status, ok := module.doDomainPageRequest("pr.example.com", 2, &exec)
	if ok || body != nil || status != 0 {
		t.Fatalf("expected do request to fail, got ok=%v status=%d body=%q", ok, status, string(body))
	}
	if exec.Error == nil {
		t.Fatal("expected request error")
	}
	if strings.Contains(*exec.Error, "very-secret-key") {
		t.Fatalf("expected api key to be redacted, got %q", *exec.Error)
	}
	if !strings.Contains(*exec.Error, "key=[redacted]") {
		t.Fatalf("expected redacted marker, got %q", *exec.Error)
	}
}

func TestDoDomainPageRequestReadBodyError(t *testing.T) {
	withShodanBaseURL(t, "http://shodan.test")
	withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return okBodyResponse(failingReadCloser{
			readErr:  errors.New("domain body failed"),
			closeErr: errors.New("domain close failed"),
		}), nil
	}))

	module := &shodanModule{apiKey: shodanTestAPIKey()}
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}

	body, status, ok := module.doDomainPageRequest("example.com", 1, &exec)
	if ok || body != nil || status != 0 {
		t.Fatalf("expected read body to fail, got ok=%v status=%d body=%q", ok, status, string(body))
	}
	if exec.Error == nil || !strings.Contains(*exec.Error, "read body") {
		t.Fatalf("expected read body error, got %+v", exec.Error)
	}
}

func TestGetShodanAPIIPIncludesOptionalQueryFlags(t *testing.T) {
	originalHistory := resolver.ShodanIPHistory
	originalMinify := resolver.ShodanIPMinify
	resolver.ShodanIPHistory = true
	resolver.ShodanIPMinify = true
	defer func() {
		resolver.ShodanIPHistory = originalHistory
		resolver.ShodanIPMinify = originalMinify
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("history") == "" {
			t.Fatalf("expected history flag to be present, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("minify") == "" {
			t.Fatalf("expected minify flag to be present, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("key") != shodanTestAPIKey() {
			t.Fatalf("expected api key query, got %q", r.URL.RawQuery)
		}
		writeTestResponse(t, w, `{"data":[],"tags":[]}`)
	}))
	defer server.Close()
	withShodanBaseURL(t, server.URL)

	module := &shodanModule{apiKey: shodanTestAPIKey()}
	markPreflightDone(module)

	exec := module.getShodanAPIIP(schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}
	if exec.RawData == "" {
		t.Fatal("expected raw data to be preserved")
	}
}

func TestDoDomainPageRequestSuccessIncludesOptionalQueryFlags(t *testing.T) {
	originalHistory := resolver.ShodanDomainHistory
	originalType := resolver.ShodanDomainType
	resolver.ShodanDomainHistory = true
	resolver.ShodanDomainType = constants.TypeTXT
	defer func() {
		resolver.ShodanDomainHistory = originalHistory
		resolver.ShodanDomainType = originalType
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("history") == "" {
			t.Fatalf("expected history flag to be present, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("type") != constants.TypeTXT {
			t.Fatalf("expected TXT type filter, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("page") != "2" {
			t.Fatalf("expected page=2, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("key") != shodanTestAPIKey() {
			t.Fatalf("expected api key query, got %q", r.URL.RawQuery)
		}
		writeTestResponse(t, w, `{"data":[],"tags":[]}`)
	}))
	defer server.Close()
	withShodanBaseURL(t, server.URL)

	module := &shodanModule{apiKey: shodanTestAPIKey()}
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}

	body, status, ok := module.doDomainPageRequest("example.com", 2, &exec)
	if !ok || status != http.StatusOK {
		t.Fatalf("expected successful page request, got ok=%v status=%d body=%q err=%v", ok, status, string(body), exec.Error)
	}
	if exec.Error != nil {
		t.Fatalf("expected no execution error, got %v", *exec.Error)
	}
	if len(body) == 0 {
		t.Fatal("expected body to be returned")
	}
}

func TestGetShodanAPIDomainBranches(t *testing.T) {
	target := schema.Entity{Type: constants.TypeSubdomain, Value: "api.example.com"}

	t.Run("invalid_key_or_credits_exhausted", func(t *testing.T) {
		module := &shodanModule{apiKey: shodanTestAPIKey(), keyInvalid: true, queryCredits: 1}
		markPreflightDone(module)

		exec := module.getShodanAPIDomain(target)
		info := requireModuleResult(t, exec.Results, constants.TypeInfo, "Shodan API key is invalid or query credits exhausted")
		if info.Category != constants.CategoryProperty {
			t.Fatalf("expected info property, got %+v", info)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusNotFound, `{"detail":"no data"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey(), queryCredits: 1}
		markPreflightDone(module)

		exec := module.getShodanAPIDomain(target)
		if exec.Error != nil {
			t.Fatalf("expected no error for not found, got %v", *exec.Error)
		}
		if exec.RawData == "" {
			t.Fatal("expected raw data for not found response")
		}
	})

	t.Run("rate_limit", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusTooManyRequests, `{"error":"slow down"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey(), queryCredits: 1}
		markPreflightDone(module)

		exec := module.getShodanAPIDomain(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "HTTP 429 Rate Limit") {
			t.Fatalf("expected 429 error, got %+v", exec.Error)
		}
	})

	t.Run("unexpected_http_status", func(t *testing.T) {
		withShodanBaseURL(t, "http://shodan.test")
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return staticResponse(http.StatusBadGateway, `{"error":"bad gateway"}`), nil
		}))

		module := &shodanModule{apiKey: shodanTestAPIKey(), queryCredits: 1}
		markPreflightDone(module)

		exec := module.getShodanAPIDomain(target)
		if exec.Error == nil || !strings.Contains(*exec.Error, "http status") {
			t.Fatalf("expected http status error, got %+v", exec.Error)
		}
	})
}

func TestDemoFunctionsAndExecRouting(t *testing.T) {
	ipModule := &shodanModule{}
	ipExec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	firstIP := ipModule.getShodanAPIIPDemo(&ipExec, schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()})
	if firstIP.RawData == "" {
		t.Fatal("expected demo ip raw data")
	}
	requireModuleResult(t, firstIP.Results, constants.TypeInfo, "⚠️ DEMO MODE: Showing sample data for Shodan IP (API key not configured)")

	secondIP := ipModule.getShodanAPIIPDemo(&schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}, schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()})
	if secondIP.RawData != "" || len(secondIP.Results) != 0 {
		t.Fatalf("expected second demo ip call to be skipped, got %+v", secondIP)
	}

	domainModule := &shodanModule{}
	domainExec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	firstDomain := domainModule.getShodanAPIDomainDemo(&domainExec, schema.Entity{Type: constants.TypeSubdomain, Value: "demo.example.com"})
	if firstDomain.RawData == "" {
		t.Fatal("expected demo domain raw data")
	}
	requireModuleResult(t, firstDomain.Results, constants.TypeInfo, "⚠️ DEMO MODE: Showing sample data for Shodan Domain (API key not configured)")

	secondDomain := domainModule.getShodanAPIDomainDemo(&schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}, schema.Entity{Type: constants.TypeSubdomain, Value: "second.example.com"})
	if secondDomain.RawData != "" || len(secondDomain.Results) != 0 {
		t.Fatalf("expected second demo domain call to be skipped, got %+v", secondDomain)
	}

	demoIPModule := &shodanModule{apiKey: demoIndicator}
	ipOutput, err := demoIPModule.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()},
		Functions: []string{constants.FuncGetShodanAPIIP},
	})
	if err != nil {
		t.Fatalf("unexpected exec error: %v", err)
	}
	if len(ipOutput.Executions) != 1 {
		t.Fatalf("expected one ip execution, got %d", len(ipOutput.Executions))
	}
	if ipOutput.Executions[0].Function != constants.FuncGetShodanAPIIP || len(ipOutput.Executions[0].Results) == 0 {
		t.Fatalf("expected demo ip execution to be routed, got %+v", ipOutput.Executions[0])
	}

	demoDomainModule := &shodanModule{apiKey: demoIndicator}
	domainOutput, err := demoDomainModule.Exec(schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeSubdomain, Value: "demo-api.example.com"},
		Functions: []string{constants.FuncGetShodanAPIDomain},
	})
	if err != nil {
		t.Fatalf("unexpected exec error: %v", err)
	}
	if len(domainOutput.Executions) != 1 {
		t.Fatalf("expected one domain execution, got %d", len(domainOutput.Executions))
	}
	if domainOutput.Executions[0].Function != constants.FuncGetShodanAPIDomain || len(domainOutput.Executions[0].Results) == 0 {
		t.Fatalf("expected demo domain execution to be routed, got %+v", domainOutput.Executions[0])
	}
}

func TestDemoFunctionsFixtureReadErrors(t *testing.T) {
	originalDemoData := demoData
	demoData = embed.FS{}
	defer func() {
		demoData = originalDemoData
	}()

	ipExec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}
	ipResult := (&shodanModule{}).getShodanAPIIPDemo(&ipExec, schema.Entity{Type: constants.TypeIPv4, Value: shodanTestAPIIPv4()})
	if ipResult.Error == nil || !strings.Contains(*ipResult.Error, "read fixture err") {
		t.Fatalf("expected demo ip fixture error, got %+v", ipResult.Error)
	}

	domainExec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	domainResult := (&shodanModule{}).getShodanAPIDomainDemo(&domainExec, schema.Entity{Type: constants.TypeSubdomain, Value: "new.example.com"})
	if domainResult.Error == nil || !strings.Contains(*domainResult.Error, "read fixture err") {
		t.Fatalf("expected demo domain fixture error, got %+v", domainResult.Error)
	}
}

func TestFetchInternetDBBranches(t *testing.T) {
	target := internetDBTestIPv4()

	t.Run("create_request_error", func(t *testing.T) {
		raw, status, err := fetchInternetDB(context.Background(), "://bad", target)
		if err == nil || !strings.Contains(err.Error(), "create request") {
			t.Fatalf("expected create request error, got status=%d raw=%q err=%v", status, string(raw), err)
		}
	})

	t.Run("do_request_error", func(t *testing.T) {
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("internetdb transport failed")
		}))
		defer withFastRetries(t)()

		raw, status, err := fetchInternetDB(context.Background(), "http://internetdb.test/192.0.2.10", target)
		if err == nil || !strings.Contains(err.Error(), "internetdb transport failed") {
			t.Fatalf("expected transport error, got status=%d raw=%q err=%v", status, string(raw), err)
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return okBodyResponse(failingReadCloser{
				readErr:  errors.New("internetdb body failed"),
				closeErr: errors.New("internetdb close failed"),
			}), nil
		}))
		defer withFastRetries(t)()

		raw, status, err := fetchInternetDB(context.Background(), "http://internetdb.test/192.0.2.11", target)
		if err == nil || !strings.Contains(err.Error(), "internetdb body failed") {
			t.Fatalf("expected body error, got status=%d raw=%q err=%v", status, string(raw), err)
		}
	})

	t.Run("rate_limit_then_success", func(t *testing.T) {
		attempts := 0
		withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			attempts++
			if attempts == 1 {
				return staticResponse(http.StatusTooManyRequests, `{"error":"slow down"}`), nil
			}
			return staticResponse(http.StatusOK, `{"ip":"192.0.2.12"}`), nil
		}))
		defer withFastRetries(t)()

		raw, status, err := fetchInternetDB(context.Background(), "http://internetdb.test/192.0.2.12", target)
		if status != http.StatusOK {
			t.Fatalf("expected final 200 status, got %d", status)
		}
		if string(raw) != `{"ip":"192.0.2.12"}` {
			t.Fatalf("unexpected raw body: %q", string(raw))
		}
		if attempts != 2 {
			t.Fatalf("expected retry sequence, got %d attempts", attempts)
		}
		if err == nil {
			t.Fatal("expected fetch to preserve last retry error for coverage path")
		}
	})
}

func TestGetInternetDBRequestFailure(t *testing.T) {
	withInternetDBHostValue(t, "http://internetdb.test")
	withDefaultTransport(t, roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("internetdb connection failed")
	}))
	defer withFastRetries(t)()

	exec := getInternetDB(schema.Entity{Type: constants.TypeIPv4, Value: internetDBTestIPv4()})
	if exec.Error == nil || !strings.Contains(*exec.Error, "internetdb request failed") {
		t.Fatalf("expected request failure, got %+v", exec.Error)
	}
}
