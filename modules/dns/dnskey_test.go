package dns

import (
	"context"
	"slices"
	"testing"
)

func TestParseDNSKEY(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected string
	}{
		{
			name:     "presentation format",
			record:   "256 3 8 AwEAAc...",
			expected: "256 3 8 AwEAAc...",
		},
		{
			name:     "wire format hex",
			record:   "\\# 6 01 01 03 08 01 02",
			expected: "257 3 RSASHA256 AQI=",
		},
		{
			name:     "unknown algorithm fallback",
			record:   "\\# 6 01 00 03 63 01 02",
			expected: "256 3 99 AQI=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseDNSKEY(tt.record)
			if res != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, res)
			}
		})
	}
}

func TestGetDNSKEYData(t *testing.T) {
	res := getDNSKEYData(context.Background(), "cloudflare.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Log("No DNSKEY records found for cloudflare.com")
	default:
		found := false
		for _, r := range res.Results {
			if r.Type == "dnskey" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected at least one 'dnskey' result")
		}
	}
}

func TestDNSKEYCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_dnskey") {
		t.Error("expected get_dnskey in capabilities")
	}
}
