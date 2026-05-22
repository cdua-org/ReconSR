package mailcrypto

import (
	"context"
	"net"
	"testing"
)

func TestParseOPENPGPKEY(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format",
			"\\# 4 01020304",
			"AQIDBA==",
		},
		{
			"passthrough non-wire",
			"Base64DataString==",
			"Base64DataString==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOPENPGPKEY(tt.input)
			if got != tt.expected {
				t.Errorf("parseOPENPGPKEY() = %q, want %q", got, tt.expected)
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
