package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestParseLOC(t *testing.T) {
	raw := "\\# 16 001313138a7bdcc0807e0a6800990bb0"
	expected := "48 51 29.600 N 2 17 40.200 E 300.00m 10.00m 10.00m 10.00m"

	parsed := parseLOC(raw)
	if parsed != expected {
		t.Errorf("parseLOC() = %q, want %q", parsed, expected)
	}

	normal := "48 51 29.600 N 2 17 40.200 E 300.00m 10m"
	if parseLOC(normal) != normal {
		t.Errorf("expected string to remain unmodified")
	}

	negativeCoordsRaw := "\\# 16 00131313758423407f81f59800990bb0"
	parsedNegative := parseLOC(negativeCoordsRaw)
	if !strings.Contains(parsedNegative, " S ") || !strings.Contains(parsedNegative, " W ") {
		t.Errorf("expected S and W for negative coords, got: %s", parsedNegative)
	}

	invalidLen := "\\# 15 001313138a7bdcc0807e0a6800990b"
	if parseLOC(invalidLen) != invalidLen {
		t.Errorf("expected raw string for invalid length")
	}

	invalidVersion := "\\# 16 011313138a7bdcc0807e0a6800990bb0"
	if parseLOC(invalidVersion) != invalidVersion {
		t.Errorf("expected raw string for invalid version")
	}

	invalidHex := "\\# 16 001313138a7bdcc0807e0a6800990bxx"
	if parseLOC(invalidHex) != invalidHex {
		t.Errorf("expected raw string for invalid hex decode")
	}

	tooLong := "\\# 17 001313138a7bdcc0807e0a6800990bb000"
	if parseLOC(tooLong) != tooLong {
		t.Errorf("expected raw string for too long data")
	}
}

func TestGetLOCData(t *testing.T) {
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
			name:       "loc_success",
			domain:     "grape.example",
			mockErr:    nil,
			mockRec:    []string{"\\# 16 001313138a7bdcc0807e0a6800990bb0"},
			mockRaw:    []byte("raw"),
			wantResult: 1,
			wantErr:    false,
		},
		{
			name:       "loc_resolve_error",
			domain:     "kiwi.example",
			mockErr:    errors.New("mock dns error"),
			mockRec:    nil,
			mockRaw:    nil,
			wantResult: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return tt.mockRec, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getLOCData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getLOCData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getLOCData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestLOCCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetLOC) {
		t.Error("expected get_loc in capabilities")
	}
}
