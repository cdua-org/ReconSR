package mailcrypto

import (
	"context"
	"net"
	"testing"
)

func TestParseSMIMEA(t *testing.T) {
	const smimeaRecord = "3 0 1 010203"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format",
			"\\# 6 030001010203",
			smimeaRecord,
		},
		{
			"passthrough non-wire",
			smimeaRecord,
			smimeaRecord,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSMIMEA(tt.input)
			if got != tt.expected {
				t.Errorf("parseSMIMEA() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMapSMIMEAContext(t *testing.T) {
	tests := []struct {
		usage    string
		selector string
		match    string
		expected string
	}{
		{"3", "0", "1", "SMIMEA: DANE-EE, Cert, SHA256"},
		{"99", "99", "99", "SMIMEA: 99, 99, 99"},
	}

	for _, tt := range tests {
		got := mapSMIMEAContext(tt.usage, tt.selector, tt.match)
		if got != tt.expected {
			t.Errorf("mapSMIMEAContext() = %q, want %q", got, tt.expected)
		}
	}
}

func TestModule_LocalIDChaining_SMIMEA(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{"\\# 6 030001010203"}, []byte("test_raw"), nil
	}

	execution := getSMIMEAData([]string{"testuser2"}, "smimea.example.net")
	requireUniqueLocalIDs(t, execution.Results)
}
