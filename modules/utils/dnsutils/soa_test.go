package dnsutils

import (
	"reflect"
	"testing"
)

func TestParseSOA(t *testing.T) {
	tests := []struct {
		expected *SOA
		name     string
		input    string
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
			input: "ns.example.net. admin.example.net. 1 100 200 300 400",
			expected: &SOA{
				NS:      "ns.example.net.",
				Mbox:    "admin.example.net.",
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
			got := ParseSOA(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseSOA() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestFormatSOAMbox(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"opsmail.example.com.", "opsmail@example.com"},
		{"adminbox.example.net.", "adminbox@example.net"},
		{"dnsbox.example.org.", "dnsbox@example.org"},
		{"no.dot.email", "no@dot.email"},
		{"single.word", "single@word"},
		{"nodotsatall", "nodotsatall"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := FormatSOAMbox(tt.input)
			if got != tt.expected {
				t.Errorf("FormatSOAMbox(%q) = %q, want %q", tt.input, got, tt.expected)
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
