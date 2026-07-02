package mailcrypto

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestParseOPENPGPKEY(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expected   string
		expectSame bool
	}{
		{
			"standard wire format",
			"\\# 4 01020304",
			"AQIDBA==",
			false,
		},
		{
			"passthrough non-wire",
			"Base64DataString==",
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
			"empty hex data",
			"\\# 4 ",
			"",
			true,
		},
		{
			"invalid hex format",
			"\\# 4 invalidhex",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOPENPGPKEY(tt.input)
			expected := tt.expected
			if tt.expectSame {
				expected = tt.input
			}
			if got != expected {
				t.Errorf("parseOPENPGPKEY() = %q, want %q", got, expected)
			}
		})
	}
}

func TestGetOPENPGPKEYDataEmptyTarget(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, target string, qtype int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		expectedTarget := GenerateMailHashDomain("testuser", "openpgp.example.net", hashPrefixOpenPGPKey)
		if target != expectedTarget {
			t.Fatalf("unexpected target: got %q want %q", target, expectedTarget)
		}
		if qtype != 61 {
			t.Fatalf("unexpected qtype: got %d want 61", qtype)
		}
		return nil, nil, nil
	}

	execution := getOPENPGPKEYData([]string{"testuser"}, "openpgp.example.net")
	if len(execution.Results) != 0 {
		t.Fatalf("expected no results, got %d", len(execution.Results))
	}
	if execution.Error != nil {
		t.Fatalf("expected no error, got %s", *execution.Error)
	}
	if execution.RawData != "" {
		t.Fatalf("expected empty raw data, got %q", execution.RawData)
	}
}

func TestModule_LocalIDChaining_OpenPGP(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{"\\# 4 01020304"}, []byte("test_raw"), nil
	}

	execution := getOPENPGPKEYData([]string{"testuser2"}, "openpgp.example.net")
	requireUniqueLocalIDs(t, execution.Results)
}

func TestGetOPENPGPKEYData_Error(t *testing.T) {
	originalResolveRecord := resolveRecord
	t.Cleanup(func() {
		resolveRecord = originalResolveRecord
	})

	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, context.DeadlineExceeded
	}

	execution := getOPENPGPKEYData([]string{"testuser_err"}, "openpgp.example.net")
	if execution.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(*execution.Error, "failed aliases: [testuser_err]") {
		t.Errorf("expected error to contain failed aliases, got %q", *execution.Error)
	}
}
