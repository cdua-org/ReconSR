package hackertarget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestModuleInterface(t *testing.T) {
	m := New()
	if m.Name() != "hackertarget" {
		t.Errorf("expected name 'hackertarget', got '%s'", m.Name())
	}

	caps, err := m.Capabilities()
	if err != nil {
		t.Errorf("Capabilities() returned error: %v", err)
	}
	if len(caps.Functions) != 1 || caps.Functions[0] != "get_hosts" {
		t.Errorf("expected Functions ['get_hosts'], got %v", caps.Functions)
	}
	if len(caps.InputTypes) != 1 || caps.InputTypes[0] != "domain" {
		t.Errorf("expected InputTypes ['domain'], got %v", caps.InputTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	m := New()
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: "domain", Value: "example.com"},
		Functions: []string{"unsupported"},
	}

	output, err := m.Exec(input)
	if err != nil {
		t.Errorf("Exec() returned error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Function != "unsupported" {
		t.Errorf("expected Function 'unsupported', got '%s'", exec.Function)
	}
	if exec.Error == nil {
		t.Error("expected Error to be set for unsupported function")
	}
}

func TestGetHostsSuccess(t *testing.T) {
	input := schema.ModuleInput{
		Target:    schema.Entity{Type: "domain", Value: "test.example.com"},
		Functions: []string{"get_hosts"},
	}

	results := parseHostSearch("sub1.test.example.com,192.168.1.1\nsub2.test.example.com,192.168.1.2\n", "example.com")

	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}

	_ = input

	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}
}

func TestGetHostsCSVFormat(t *testing.T) {
	const subdomainType = "subdomain"
	const ipv4Type = "ipv4"

	body := "domain1.example.com,1.2.3.4\ndomain2.example.com,5.6.7.8\n"
	results := parseHostSearch(body, "example.com")

	hasSubdomain := false
	hasIP := false
	for _, r := range results {
		if r.Type == subdomainType {
			hasSubdomain = true
		}
		if r.Type == ipv4Type {
			hasIP = true
		}
	}
	if !hasSubdomain {
		t.Error("expected at least one subdomain result")
	}
	if !hasIP {
		t.Error("expected at least one ip result")
	}
}

func TestGetHostsInvalidCSV(t *testing.T) {
	body := "error: rate limit exceeded\n"
	if isValidCSVFormat(body) {
		t.Error("expected invalid CSV to fail validation")
	}
}

func TestIsQuotaExceeded(t *testing.T) {
	tests := []struct {
		name     string
		count    string
		quota    string
		expected bool
	}{
		{"both empty", "", "", false},
		{"count empty", "", "100", false},
		{"quota empty", "50", "", false},
		{"count less than quota", "50", "100", false},
		{"count equals quota", "100", "100", true},
		{"count exceeds quota", "150", "100", true},
		{"invalid count", "abc", "100", false},
		{"invalid quota", "50", "xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			header.Set("X-Api-Count", tt.count)
			header.Set("X-Api-Quota", tt.quota)

			result := isQuotaExceeded(header)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIsValidCSVFormat(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"valid single line", "domain.example.com,1.2.3.4", true},
		{"valid multiple lines", "a.example.com,1.1.1.1\nb.example.com,2.2.2.2", true},
		{"empty body", "", true},
		{"no comma", "domain.example.com", false},
		{"invalid ip", "domain.example.com,not.an.ip", false},
		{"empty lines", "domain.example.com,1.2.3.4\n\n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCSVFormat(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestParseHostSearch(t *testing.T) {
	const ipv4Type = "ipv4"
	body := "sub1.example.com,192.168.1.1\nsub2.example.com,192.168.1.2\n"

	results := parseHostSearch(body, "example.com")

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	if results[0].Type != "subdomain" || results[0].Value != "sub1.example.com" {
		t.Errorf("first result: expected {subdomain, sub1.example.com}, got %+v", results[0])
	}
	if results[1].Type != ipv4Type || results[1].Value != "192.168.1.1" {
		t.Errorf("second result: expected {ipv4, 192.168.1.1}, got %+v", results[1])
	}
	if results[2].Type != "subdomain" || results[2].Value != "sub2.example.com" {
		t.Errorf("third result: expected {subdomain, sub2.example.com}, got %+v", results[2])
	}
	if results[3].Type != ipv4Type || results[3].Value != "192.168.1.2" {
		t.Errorf("fourth result: expected {ipv4, 192.168.1.2}, got %+v", results[3])
	}
}

func TestDoRequestWithAPIKey(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test.example.com,1.2.3.4\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, _, _, _ = doRequest(context.Background(), "example.com", "mock_api_key")

	expectedURL := "/hostsearch/?q=example.com&apikey=mock_api_key"
	if capturedURL != expectedURL {
		t.Errorf("expected request URL to be %q, got %q", expectedURL, capturedURL)
	}
}

func TestDoRequestWithoutAPIKey(t *testing.T) {
	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test.example.com,1.2.3.4\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, _, _, _ = doRequest(context.Background(), "example.com", "")

	expectedURL := "/hostsearch/?q=example.com"
	if capturedURL != expectedURL {
		t.Errorf("expected request URL to be %q, got %q", expectedURL, capturedURL)
	}
}

func TestDoRequestQuotaExceeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Api-Count", "100")
		w.Header().Set("X-Api-Quota", "100")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test.example.com,1.2.3.4\n")); err != nil {
			t.Errorf("test server write error: %v", err)
		}
	}))
	defer server.Close()

	originalBaseURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalBaseURL }()

	_, isQuota, _, _ := doRequest(context.Background(), "example.com", "")
	if !isQuota {
		t.Error("expected doRequest to detect quota exceeded")
	}
}
