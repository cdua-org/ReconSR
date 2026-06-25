package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseDS(t *testing.T) {
	const parsedDSRecord = "3437 8 2 1234567890ABCDEF1234567890ABCDEF"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard ds wire format",
			"\\# 20 0d6d08021234567890abcdef1234567890abcdef",
			parsedDSRecord,
		},
		{
			"passthrough ds text",
			parsedDSRecord,
			parsedDSRecord,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDS(tt.input)
			if got != tt.expected {
				t.Errorf("parseDS() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetDSData(t *testing.T) {
	origResolve := resolveRecordFunc
	defer func() { resolveRecordFunc = origResolve }()

	tests := []struct {
		name       string
		domain     string
		mockErr    error
		mockRec    []string
		mockRaw    []byte
		wantResult int
		wantErr    bool
	}{
		{
			name:       "ds_success",
			domain:     "example.com",
			mockErr:    nil,
			mockRec:    []string{"\\# 20 0d6d08021234567890abcdef1234567890abcdef"},
			mockRaw:    []byte("raw"),
			wantResult: 1,
			wantErr:    false,
		},
		{
			name:       "ds_resolve_error",
			domain:     "error.example.com",
			mockErr:    errors.New("mock dns error"),
			mockRec:    nil,
			mockRaw:    nil,
			wantResult: 0,
			wantErr:    true,
		},
		{
			name:       "malformed record length",
			domain:     "malformed.example.com",
			mockErr:    nil,
			mockRec:    []string{"invalid ds record"},
			mockRaw:    []byte("raw"),
			wantResult: 0,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return tt.mockRec, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getDSData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getDSData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getDSData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestDSCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDS) {
		t.Error("expected get_ds in capabilities")
	}
}
