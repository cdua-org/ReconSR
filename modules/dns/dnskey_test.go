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
			expected: "257 3 " + constants.AlgRSASHA256 + " AQI=",
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
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{
			"257 3 8 AwEAAc...",
			"256 3 8 AwEAAcZSK...",
			"255 3 8 AwEAAc...",
			"257 3 999 AwEAAc...",
			"257 3 invalid AwEAAc...",
			"257 3 99 AwEAAc...",
			"malformed record",
		}, []byte("mocked raw data"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDNSKEYData(context.Background(), "test.example", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}

	if len(res.Results) != 5 {
		t.Errorf("expected 5 results, got %d", len(res.Results))
	}
	if res.RawData == "" {
		t.Error("expected RawData to be set")
	}
}

func TestGetDNSKEYDataEmpty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDNSKEYData(context.Background(), "empty.example", modutil.NewLocalIDGenerator())
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetDNSKEYData_Error(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, errors.New("mock dnskey error")
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDNSKEYData(context.Background(), "error.example", modutil.NewLocalIDGenerator())
	if res.Error == nil {
		t.Error("expected error, got nil")
	}
}

func TestDNSKEYCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDNSKEY) {
		t.Error("expected get_dnskey in capabilities")
	}
}
