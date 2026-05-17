package dnsutils

import (
	"testing"
)

func TestParseNAPTR(t *testing.T) {
	tests := []struct {
		name                string
		raw                 string
		expectedService     string
		expectedReplacement string
		expectedRegexp      string
		expectedRegexpTgt   string
	}{
		{
			name:                "valid SIP D2U",
			raw:                 "100 50 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.net.",
			expectedService:     "SIP+D2U",
			expectedReplacement: "_sip._udp.example.net.",
		},
		{
			name:                "valid SIPS D2T",
			raw:                 "90 50 \"s\" \"SIPS+D2T\" \"\" _sips._tcp.example.org.",
			expectedService:     "SIPS+D2T",
			expectedReplacement: "_sips._tcp.example.org.",
		},
		{
			name:                "regexp with replacement",
			raw:                 "10 100 \"u\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" .",
			expectedService:     "E2U+sip",
			expectedReplacement: "",
			expectedRegexp:      "!^.*$!sip:info@example.com!",
			expectedRegexpTgt:   "sip:info@example.com",
		},
		{
			name:                "missing regexp field 5 parts",
			raw:                 "10 100 \"s\" \"SIP+D2T\" _sip._tcp.example.org.",
			expectedService:     "SIP+D2T",
			expectedReplacement: "_sip._tcp.example.org.",
		},
		{
			name:              "missing replacement field 5 parts",
			raw:               "10 100 \"u\" \"E2U+sip\" \"!^.*$!sip:test!\"",
			expectedService:   "E2U+sip",
			expectedRegexp:    "!^.*$!sip:test!",
			expectedRegexpTgt: "sip:test",
		},
		{
			name:                "invalid short record",
			raw:                 "100 50 \"s\"",
			expectedService:     "",
			expectedReplacement: "",
		},
		{
			name:                "wire format skipped",
			raw:                 "\\# 23 00",
			expectedService:     "",
			expectedReplacement: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseNAPTR(tt.raw)
			if tt.expectedService == "" && tt.expectedReplacement == "" {
				if result != nil {
					t.Fatalf("expected nil for invalid/skipped record, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected result, got nil")
			}
			if result.Service != tt.expectedService {
				t.Errorf("expected Service %q, got %q", tt.expectedService, result.Service)
			}
			if result.Replacement != tt.expectedReplacement {
				t.Errorf("expected Replacement %q, got %q", tt.expectedReplacement, result.Replacement)
			}
			if result.Regexp != tt.expectedRegexp {
				t.Errorf("expected Regexp %q, got %q", tt.expectedRegexp, result.Regexp)
			}
			if result.RegexpTarget != tt.expectedRegexpTgt {
				t.Errorf("expected RegexpTarget %q, got %q", tt.expectedRegexpTgt, result.RegexpTarget)
			}
			if result.Formatted != tt.raw {
				t.Errorf("expected Formatted %q, got %q", tt.raw, result.Formatted)
			}
		})
	}
}
