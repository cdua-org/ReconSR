package dnsutils

import (
	"testing"
)

func TestParseURI(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		expectedTarget string
		expectedFmt    string
	}{
		{
			name:           "valid wire format",
			raw:            "\\# 23 000A0064687474703A2F2F6578616D706C652E636F6D",
			expectedTarget: "http://example.com",
			expectedFmt:    "10 100 \"http://example.com\"",
		},
		{
			name:           "valid plain text without quotes",
			raw:            "10 100 http://example.net",
			expectedTarget: "http://example.net",
			expectedFmt:    "10 100 \"http://example.net\"",
		},
		{
			name:           "valid plain text with quotes",
			raw:            "20 200 \"https://example.org\"",
			expectedTarget: "https://example.org",
			expectedFmt:    "20 200 \"https://example.org\"",
		},
		{
			name:           "valid plain text with spaces in target",
			raw:            "30 300 \"http://api.example.com/some path\"",
			expectedTarget: "http://api.example.com/some path",
			expectedFmt:    "30 300 \"http://api.example.com/some path\"",
		},
		{
			name:           "invalid short string",
			raw:            "10 100",
			expectedTarget: "",
			expectedFmt:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseURI(tt.raw)
			if tt.expectedTarget == "" {
				if result != nil {
					t.Fatalf("expected nil for invalid record, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected result, got nil")
			}
			if result.Target != tt.expectedTarget {
				t.Errorf("expected Target %q, got %q", tt.expectedTarget, result.Target)
			}
			if result.Formatted != tt.expectedFmt {
				t.Errorf("expected Formatted %q, got %q", tt.expectedFmt, result.Formatted)
			}
		})
	}
}
