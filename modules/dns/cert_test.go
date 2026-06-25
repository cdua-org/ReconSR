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

func TestParseCERT(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard wire format PGP",
			"\\# 10 00033039004151493d0a",
			"3 12345 0 QVFJPQo=",
		},
		{
			"passthrough cert text",
			"3 12345 0 Base64Data",
			"3 12345 0 Base64Data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCERT(tt.input)
			if got != tt.expected {
				t.Errorf("parseCERT() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetCERTData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{
			"3 12345 5 Base64Data",
			"999 12345 99 Base64Data",
			"short record",
		}, []byte("mock"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	execution := getCERTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Fatalf("unexpected network error: %v", *execution.Error)
	}

	if len(execution.Results) != 2 {
		t.Fatalf("expected 2 CERT results, got %d", len(execution.Results))
	}
	if !strings.Contains(execution.Results[0].Context, "PGP") || !strings.Contains(execution.Results[0].Context, "RSASHA1") {
		t.Errorf("expected translated names in Context, got: %s", execution.Results[0].Context)
	}
}

func TestGetCERTData_Error(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, errors.New("mock network error")
	}
	defer func() { resolveRecordFunc = oldResolve }()

	execution := getCERTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error == nil {
		t.Errorf("expected error from mocked failure")
	}
}

func TestCERTCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetCERT) {
		t.Error("expected get_cert in capabilities")
	}
}
