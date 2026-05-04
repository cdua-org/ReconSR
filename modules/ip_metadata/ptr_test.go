package ip_metadata

import (
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type mockTransport struct {
	oldTransport http.RoundTripper
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Query().Get("type") == "12" && strings.Contains(req.URL.Query().Get("name"), "1.2.3.4.in-addr.arpa.") {
		body := `{"Status": 0, "Answer": [{"name": "1.2.3.4.in-addr.arpa.", "type": 12, "data": "*.invalid.name.com."}]}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	}
	if m.oldTransport != nil {
		return m.oldTransport.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestGetPTRDataInvalidNameMock(t *testing.T) {
	oldTransport := http.DefaultTransport
	http.DefaultTransport = &mockTransport{oldTransport: oldTransport}
	defer func() { http.DefaultTransport = oldTransport }()

	res := getPTRData("4.3.2.1")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected results, got none")
	}
	if res.Results[0].Value != "*.invalid.name.com" {
		t.Errorf("expected '*.invalid.name.com', got '%s'", res.Results[0].Value)
	}
}

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(caps.Functions) == 0 {
		t.Fatal("expected functions, got none")
	}

	if !slices.Contains(caps.Functions, "get_ptr") {
		t.Error("expected get_ptr in capabilities")
	}
}

func TestExecUnsupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: "ipv4", Value: "8.8.8.8"},
		Functions: []string{"unknown_func"},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	if out.Executions[0].Error == nil {
		t.Error("expected error for unsupported function")
	}
}

func TestModuleName(t *testing.T) {
	mod := New()
	if mod.Name() != "ip_metadata" {
		t.Errorf("expected name 'ip_metadata', got '%s'", mod.Name())
	}
}

func TestExecSupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: "ipv4", Value: "8.8.8.8"},
		Functions: []string{"get_ptr"},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
}

func TestGetPTRData(t *testing.T) {
	res := getPTRData("8.8.8.8")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one PTR record for 8.8.8.8")
	case res.Results[0].Type != "ptr":
		t.Errorf("expected type 'ptr', got '%s'", res.Results[0].Type)
	}
}

func TestGetPTRDataNoHost(t *testing.T) {
	res := getPTRData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for non-existent PTR, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetPTRDataInvalidIP(t *testing.T) {
	res := getPTRData("invalid-ip")
	if res.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestGetPTRDataDebug(t *testing.T) {
	t.Log("Testing debug output")
	const debugStr = "true"
	const debugFalse = "false"
	resolver.Options["Debug"] = debugStr
	defer func() { resolver.Options["Debug"] = debugFalse }()

	getPTRData("8.8.8.8")
	getPTRData("192.0.2.1")
	getPTRData("invalid")
}

func TestGetPTRDataTimeout(t *testing.T) {
	oldTimeout := resolver.Timeout
	resolver.Timeout = 1 * time.Nanosecond
	defer func() { resolver.Timeout = oldTimeout }()

	res := getPTRData("8.8.8.8")
	if res.Error == nil {
		t.Error("expected network error/timeout with 1ns timeout, got nil")
	}
}
