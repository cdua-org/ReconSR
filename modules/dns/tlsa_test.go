package dns

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseTLSA(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard tlsa wire format",
			"\\# 35 03 01 01 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"3 1 1 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			"passthrough tlsa text",
			"3 1 1 abcdef0123456789",
			"3 1 1 abcdef0123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTLSA(tt.input)
			if got != tt.expected {
				t.Errorf("parseTLSA() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetTLSAData(t *testing.T) {
	tests := []struct {
		mockError     error
		name          string
		target        string
		mockRecords   []string
		expectedCount int
		cancelCtx     bool
	}{
		{
			mockError:     nil,
			name:          "tlsa lookup success",
			target:        "gettlsa.example.com",
			mockRecords:   []string{"\\# 35 03 01 01 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
			expectedCount: 8,
		},
		{
			mockError:     nil,
			name:          "tlsa lookup empty",
			target:        "empty.gettlsa.example.net",
			mockRecords:   []string{},
			expectedCount: 0,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "tlsa lookup err",
			target:        "error.gettlsa.example.org",
			mockRecords:   nil,
			expectedCount: 0,
		},
		{
			name:          "tlsa context canceled",
			target:        "cancel.gettlsa.example.com",
			expectedCount: 0,
			cancelCtx:     true,
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

			ctx := context.Background()
			if tt.cancelCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			execution := getTLSAData(ctx, tt.target, modutil.NewLocalIDGenerator())

			if execution.Error != nil {
				t.Errorf("unexpected error: %v", *execution.Error)
			}
			if len(execution.Results) != tt.expectedCount {
				t.Errorf("expected %d results, got %d", tt.expectedCount, len(execution.Results))
			}
		})
	}
}

func TestTLSACapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetTLSA) {
		t.Error("expected get_tlsa in capabilities")
	}
}
