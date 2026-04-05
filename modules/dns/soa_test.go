package dns

import (
	"reflect"
	"slices"
	"testing"
)

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

func TestGetSOAData(t *testing.T) {
	res := getSOAData("example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Log("No SOA records found for example.com")
	default:
		// We expect 7 results (Primary NS, Responsible Email, Serial, Refresh, Retry, Expire, MinTTL)
		if len(res.Results) != 7 {
			t.Errorf("expected 7 results, got %d", len(res.Results))
		}
	}
}

func TestSOACapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_soa") {
		t.Error("expected get_soa in capabilities")
	}
}
