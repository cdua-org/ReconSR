package dnsutils

import (
	"testing"
)

func TestParseIPSECKEY(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format no gateway",
			"\\# 6 0A0002010203",
			"10 0 2 . AQID",
		},
		{
			"standard wire format ipv4 gateway",
			"\\# 10 0A0102C0000226010203",
			"10 1 2 192.0.2.38 AQID",
		},
		{
			"passthrough non-wire",
			"10 1 2 192.0.2.38 AQO",
			"10 1 2 192.0.2.38 AQO",
		},
		{
			"standard wire format ipv6 gateway",
			"\\# 22 0A020220010DB8000000000000000000000001010203",
			"10 2 2 2001:db8::1 AQID",
		},
		{
			"standard wire format domain gateway",
			"\\# 23 0A03020376706E076578616D706C6503636F6D00010203",
			"10 3 2 vpn.example.com AQID",
		},
		{
			"out of bounds ipv4",
			"\\# 5 0A01020102",
			"10 1 2 <unknown> AQI=",
		},
		{
			"unknown gateway type",
			"\\# 6 0A0902010203",
			"10 9 2 <unknown> AQID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPSECKEY(tt.input)
			if result == nil {
				t.Fatalf("ParseIPSECKEY() returned nil for %q", tt.input)
			}
			if result.Formatted != tt.expected {
				t.Errorf("ParseIPSECKEY().Formatted = %q, want %q", result.Formatted, tt.expected)
			}
		})
	}
}
