package dns

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseSSHFP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"RSA SHA-256 wire format",
			"\\# 34 01 02 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"RSA SHA-256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			"Ed25519 SHA-256 wire format",
			"\\# 34 04 02 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			"Ed25519 SHA-256 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			"passthrough sshfp text",
			"1 2 abcdef0123456789",
			"1 2 abcdef0123456789",
		},
		{
			"unknown algorithm and type wire format",
			"\\# 04 63 63 aabb",
			"Unknown(99) Unknown(99) aabb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSHFP(tt.input)
			if got != tt.expected {
				t.Errorf("parseSSHFP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetSSHFPData(t *testing.T) {
	tests := []struct {
		mockError     error
		name          string
		target        string
		mockRecords   []string
		expectedCount int
		expectError   bool
	}{
		{
			mockError:     nil,
			name:          "sshfp lookup success",
			target:        "getsshfp.example.com",
			mockRecords:   []string{"3 4 123456"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			mockError:     nil,
			name:          "sshfp lookup empty",
			target:        "empty.getsshfp.example.net",
			mockRecords:   []string{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "sshfp lookup err",
			target:        "error.getsshfp.example.org",
			mockRecords:   nil,
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origResolveRecordFunc := resolveRecordFunc
			defer func() { resolveRecordFunc = origResolveRecordFunc }()

			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				if tt.mockError != nil {
					return nil, nil, tt.mockError
				}
				return tt.mockRecords, []byte("mock raw data"), nil
			}

			execution := getSSHFPData(context.Background(), tt.target, modutil.NewLocalIDGenerator())

			if tt.expectError {
				if execution.Error == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if execution.Error != nil {
					t.Errorf("unexpected error: %v", *execution.Error)
				}
				if len(execution.Results) != tt.expectedCount {
					t.Errorf("expected %d results, got %d", tt.expectedCount, len(execution.Results))
				}
			}
		})
	}
}

func TestSSHFPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSSHFP) {
		t.Error("expected get_sshfp in capabilities")
	}
}
