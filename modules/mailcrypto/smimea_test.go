package mailcrypto

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestParseSMIMEA(t *testing.T) {
	const smimeaRecord = "3 0 1 010203"

	tests := []struct {
		name       string
		input      string
		expected   string
		expectSame bool
	}{
		{
			"standard wire format",
			"\\# 6 030001010203",
			smimeaRecord,
			false,
		},
		{
			"passthrough non-wire",
			smimeaRecord,
			"",
			true,
		},
		{
			"invalid format missing spaces",
			"\\# 4",
			"",
			true,
		},
		{
			"invalid hex format",
			"\\# 4 invalidhex",
			"",
			true,
		},
		{
			"short hex data",
			"\\# 4 010203",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSMIMEA(tt.input)
			expected := tt.expected
			if tt.expectSame {
				expected = tt.input
			}
			if got != expected {
				t.Errorf("parseSMIMEA() = %q, want %q", got, expected)
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

func TestGetSMIMEAData_ElseBranch(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{"invalid record"}, nil, nil
	}

	execution := getSMIMEAData([]string{"testuser_else"}, "smimea.example.net")
	if len(execution.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(execution.Results))
	}
	if execution.Results[0].Value != "invalid record" {
		t.Errorf("expected 'invalid record', got %q", execution.Results[0].Value)
	}
}

func TestGetSMIMEAData_Error(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, context.DeadlineExceeded
	}

	execution := getSMIMEAData([]string{"testuser_err"}, "smimea.example.net")
	if execution.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(*execution.Error, "failed aliases: [testuser_err]") {
		t.Errorf("expected error to contain failed aliases, got %q", *execution.Error)
	}
}
