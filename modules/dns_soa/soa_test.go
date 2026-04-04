package dns_soa

import (
	"reflect"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedFuncs := []string{"get_soa"}
	if !reflect.DeepEqual(caps.Functions, expectedFuncs) {
		t.Errorf("Functions mismatch: got %v, want %v", caps.Functions, expectedFuncs)
	}

	expectedTypes := []string{"domain", "subdomain"}
	if !reflect.DeepEqual(caps.InputTypes, expectedTypes) {
		t.Errorf("InputTypes mismatch: got %v, want %v", caps.InputTypes, expectedTypes)
	}
}

func TestExecUnsupportedFunction(t *testing.T) {
	mod := New()
	input := schema.ModuleInput{
		Target: schema.Entity{
			Type:  "domain",
			Value: "example.com",
		},
		Functions: []string{"invalid_func"},
	}

	output, err := mod.Exec(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	exec := output.Executions[0]
	if exec.Function != "invalid_func" {
		t.Errorf("expected function invalid_func, got %s", exec.Function)
	}

	if exec.Error == nil {
		t.Fatal("expected error, got nil")
	}

	expectedErr := "unsupported function: invalid_func"
	if *exec.Error != expectedErr {
		t.Errorf("expected error %q, got %q", expectedErr, *exec.Error)
	}
}

func TestParseSOA(t *testing.T) {
	//nolint:govet // test struct field order doesn't need optimization
	tests := []struct {
		name     string
		input    string
		expected *SOA
	}{
		{
			name:  "valid SOA",
			input: "ns1.example.com. hostmaster.example.com. 2024031501 7200 3600 1209600 86400",
			expected: &SOA{
				NS:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  2024031501,
				Refresh: 7200,
				Retry:   3600,
				Expire:  1209600,
				MinTTL:  86400,
			},
		},
		{
			name:  "minimal SOA",
			input: "ns.example.com. admin.example.com. 1 100 200 300 400",
			expected: &SOA{
				NS:      "ns.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  1,
				Refresh: 100,
				Retry:   200,
				Expire:  300,
				MinTTL:  400,
			},
		},
		{
			name:     "invalid too few fields",
			input:    "ns.example.com. admin.example.com.",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSOA(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseSOA() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestFormatMbox(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hostmaster.example.com.", "hostmaster@example.com"},
		{"admin.example.com.", "admin@example.com"},
		{"dns.cloudflare.com.", "dns@cloudflare.com"},
		{"no.dot.email", "no@dot.email"},
		{"single.word", "single@word"},
		{"nodotsatall", "nodotsatall"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := formatMbox(tt.input)
			if got != tt.expected {
				t.Errorf("formatMbox(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"12345", 12345},
		{"0", 0},
		{"4294967295", 4294967295},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseUint(tt.input)
			if got != tt.expected {
				t.Errorf("parseUint(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}
