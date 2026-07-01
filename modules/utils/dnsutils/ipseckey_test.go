package dnsutils

import (
	"testing"
)

func TestParseIPSECKEY(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantNil  bool
	}{
		{
			"standard wire format no gateway",
			"\\# 6 0A0002010203",
			"10 0 2 . AQID",
			false,
		},
		{
			"standard wire format ipv4 gateway",
			"\\# 10 0A0102C0000226010203",
			"10 1 2 192.0.2.38 AQID",
			false,
		},
		{
			"passthrough non-wire",
			"10 1 2 192.0.2.38 AQO",
			"10 1 2 192.0.2.38 AQO",
			false,
		},
		{
			"standard wire format ipv6 gateway",
			"\\# 22 0A020220010DB8000000000000000000000001010203",
			"10 2 2 2001:db8::1 AQID",
			false,
		},
		{
			"standard wire format domain gateway",
			"\\# 23 0A03020376706E076578616D706C6503636F6D00010203",
			"10 3 2 vpn.example.com AQID",
			false,
		},
		{
			"out of bounds ipv4",
			"\\# 5 0A01020102",
			"10 1 2 <unknown> AQI=",
			false,
		},
		{
			"unknown gateway type",
			"\\# 6 0A0902010203",
			"10 9 2 <unknown> AQID",
			false,
		},
		{
			"invalid plain text format",
			"10 1 2",
			"",
			true,
		},
		{
			"out of bounds ipv6",
			"\\# 5 0A02020102",
			"10 2 2 <unknown> AQI=",
			false,
		},
		{
			"empty domain",
			"\\# 3 0A0302",
			"10 3 2 <unknown> ",
			false,
		},
		{
			"root domain",
			"\\# 4 0A030200",
			"10 3 2 . ",
			false,
		},
		{
			"domain out of bounds",
			"\\# 5 0A03020576",
			"10 3 2 <unknown> BXY=",
			false,
		},
		{
			"unterminated domain",
			"\\# 5 0A03020176",
			"10 3 2 <unknown> AXY=",
			false,
		},
		{
			"pointer in domain",
			"\\# 5 0A0302C001",
			"10 3 2 <unknown> wAE=",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIPSECKEY(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Fatalf("ParseIPSECKEY() returned %+v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("ParseIPSECKEY() returned nil for %q", tt.input)
			}
			if result.Formatted != tt.expected {
				t.Errorf("ParseIPSECKEY().Formatted = %q, want %q", result.Formatted, tt.expected)
			}
		})
	}
}
