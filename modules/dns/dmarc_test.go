package dns

import (
	"context"
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetDMARCData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, target string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		if target == "_dmarc.example.com" {
			return []string{"v=DMARC1; p=reject; rua=mailto:admin@example.com"}, []byte("raw"), nil
		}
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDMARCData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected DMARC records")
	}
}

func TestGetDMARCDataEmpty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDMARCData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetDMARCData_FallbackError(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		res, err := fallback(ctx, nil)
		if err != nil && !strings.Contains(err.Error(), "plain lookup dmarc failed") {
			t.Errorf("unexpected error from fallback: %v", err)
		}
		return res, nil, err
	}
	defer func() { resolveRecordFunc = oldResolve }()

	oldPlain := plainLookupTXT
	plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
		return nil, errors.New("mock txt error")
	}
	defer func() { plainLookupTXT = oldPlain }()

	res := getDMARCData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error == nil {
		t.Error("expected error from lookup, got nil")
	}
}

func TestGetDMARCData_ContextCancelled(t *testing.T) {
	oldResolve := resolveRecordFunc
	defer func() { resolveRecordFunc = oldResolve }()
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := getDMARCData(ctx, "example.com", modutil.NewLocalIDGenerator())

	if res.Error == nil {
		t.Error("expected error from context cancellation, got nil")
	}
}

func TestGetDMARCData_FallbackSuccess(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		res, err := fallback(ctx, nil)
		return res, nil, err
	}
	defer func() { resolveRecordFunc = oldResolve }()

	oldPlain := plainLookupTXT
	plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
		return []string{"v=DMARC1; p=none"}, nil
	}
	defer func() { plainLookupTXT = oldPlain }()

	res := getDMARCData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected DMARC results from fallback")
	}
}

func TestDMARCCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDMARC) {
		t.Error("expected get_dmarc in capabilities")
	}
}

func TestFilterDMARC(t *testing.T) {
	const (
		quarantineRecord = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
		noneRecord       = "v=DMARC1; p=none"
	)

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid DMARC record",
			input:    []string{quarantineRecord},
			expected: []string{quarantineRecord},
		},
		{
			name:     "multiple records with DMARC",
			input:    []string{"v=DKIM1", noneRecord, "v=SPF1"},
			expected: []string{noneRecord},
		},
		{
			name:     "no DMARC records",
			input:    []string{"v=DKIM1", "v=SPF1"},
			expected: nil,
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "case insensitive - different case not matched",
			input:    []string{"V=DMARC1; p=reject"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("filterDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProcessDMARCEmailsSkipsInvalidAndNormalizes(t *testing.T) {
	source := &schema.EntityRef{Type: constants.TypeDMARC, Value: "v=DMARC1"}
	parsed := map[string]string{"rua": "mailto:Admin@EXAMPLE.COM,mailto:bad@@example.com"}
	results := processDMARCEmails("rua.dmarc.example.com", parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != constants.TypeEmail {
		t.Fatalf("expected type email, got %q", results[0].Type)
	}

	if results[0].Value != "Admin@example.com" {
		t.Fatalf("expected normalized email, got %q", results[0].Value)
	}

	if results[0].Context != "DMARC RUA #1" {
		t.Fatalf("expected indexed context, got %q", results[0].Context)
	}

	if results[0].OutOfScope {
		t.Fatal("expected in-scope email")
	}

	if results[0].Source != source {
		t.Fatal("expected source to be attached")
	}
}

func TestProcessDMARCEmailsUsesValidatedType(t *testing.T) {
	source := &schema.EntityRef{Type: constants.TypeDMARC, Value: "v=DMARC1"}
	parsed := map[string]string{"ruf": `mailto:"john"@example.com`}
	results := processDMARCEmails("ruf.dmarc.example.com", parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != constants.TypeEmailExtra {
		t.Fatalf("expected type email-extra, got %q", results[0].Type)
	}

	if results[0].Value != `"john"@example.com` {
		t.Fatalf("expected validated email-extra value, got %q", results[0].Value)
	}

	if results[0].Context != "DMARC RUF" {
		t.Fatalf("expected non-indexed context, got %q", results[0].Context)
	}
	if results[0].Source != source {
		t.Fatal("expected source to be attached")
	}
}
