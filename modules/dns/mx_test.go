package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestParseMX(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected mxRecord
		wantErr  bool
	}{
		{
			name:     "valid MX record",
			input:    "10 mail.example.com.",
			expected: mxRecord{host: "mail.example.com", pref: 10},
			wantErr:  false,
		},
		{
			name:     "MX with high priority",
			input:    "1 mx.example.net.",
			expected: mxRecord{host: "mx.example.net", pref: 1},
			wantErr:  false,
		},
		{
			name:     "invalid - too few fields",
			input:    "mail.example.com.",
			expected: mxRecord{},
			wantErr:  true,
		},
		{
			name:     "invalid mx host format",
			input:    "\\# 2 broken",
			expected: mxRecord{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMX(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got.host != tt.expected.host || got.pref != tt.expected.pref) {
				t.Errorf("parseMX() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestBuildMXHostResult(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		target    string
		wantValue string
		wantType  string
		wantNil   bool
		wantOOS   bool
	}{
		{
			name:      "in scope subdomain host",
			host:      "MAIL.MX-SCOPE.EXAMPLE.COM",
			target:    "mx-scope.example.com",
			wantType:  constants.TypeSubdomain,
			wantValue: "mail.mx-scope.example.com",
		},
		{
			name:    "invalid host is skipped",
			host:    "bad host",
			target:  "mx-invalid.example.com",
			wantNil: true,
		},
		{
			name:    "self referential host is skipped",
			host:    "mx-self.example.com",
			target:  "mx-self.example.com",
			wantNil: true,
		},
		{
			name:      "out of scope host",
			host:      "relay.mx-external.example.org",
			target:    "mx-oos.example.com",
			wantType:  constants.TypeSubdomain,
			wantValue: "relay.mx-external.example.org",
			wantOOS:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &schema.EntityRef{Type: constants.TypeMX, Value: "10 " + tt.host}
			result := buildMXHostResult(source, tt.host, tt.target, modutil.NewLocalIDGenerator())
			if tt.wantNil {
				if result != nil {
					t.Fatalf("expected nil result, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Type != tt.wantType {
				t.Fatalf("type = %q, want %q", result.Type, tt.wantType)
			}
			if !slices.Contains(result.Tags, constants.TagMX) {
				t.Fatalf("missing tag %q", constants.TagMX)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("value = %q, want %q", result.Value, tt.wantValue)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("out_of_scope = %v, want %v", result.OutOfScope, tt.wantOOS)
			}
			if result.Source == nil || result.Source.Type != source.Type || result.Source.Value != source.Value {
				t.Fatalf("expected source %+v, got %+v", source, result.Source)
			}
		})
	}
}

func TestGetMXData(t *testing.T) {
	origResolve := resolveRecordFunc
	origPlain := plainLookupMX
	defer func() {
		resolveRecordFunc = origResolve
		plainLookupMX = origPlain
	}()

	tests := []struct {
		name         string
		domain       string
		mockErr      error
		fallbackErr  error
		mockRec      []string
		mockRaw      []byte
		fallbackMXs  []*net.MX
		wantResult   int
		callFallback bool
		wantErr      bool
	}{
		{
			name:         "mx_success_records",
			domain:       "cherry-mx.example",
			mockErr:      nil,
			mockRec:      []string{"10 mx1.example.com.", "20 mx2.example.com.", "invalid_no_pref"},
			mockRaw:      []byte("raw"),
			callFallback: false,
			wantResult:   4,
			wantErr:      false,
		},
		{
			name:         "mx_success_empty",
			domain:       "empty-mx.example",
			mockErr:      nil,
			mockRec:      []string{"invalid_only"},
			mockRaw:      []byte("raw"),
			callFallback: false,
			wantResult:   0,
			wantErr:      false,
		},
		{
			name:         "mx_resolve_error",
			domain:       "berry-mx.example",
			mockErr:      errors.New("mock dns error"),
			callFallback: false,
			wantResult:   0,
			wantErr:      true,
		},
		{
			name:         "mx_fallback_success",
			domain:       "date.example",
			mockErr:      nil,
			callFallback: true,
			fallbackErr:  nil,
			fallbackMXs: []*net.MX{
				{Host: "fallback.example.com.", Pref: 50},
			},
			wantResult: 2,
			wantErr:    false,
		},
		{
			name:         "mx_fallback_error",
			domain:       "fig.example",
			mockErr:      errors.New("mock dns error"),
			callFallback: true,
			fallbackErr:  errors.New("fallback failed"),
			wantResult:   0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainLookupMX = func(_ context.Context, _ *net.Resolver, _ string) ([]*net.MX, error) {
				return tt.fallbackMXs, tt.fallbackErr
			}

			resolveRecordFunc = func(_ context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				if tt.callFallback && fallback != nil {
					res, err := fallback(context.Background(), nil)
					if err != nil {
						return nil, nil, tt.mockErr
					}
					return res, tt.mockRaw, nil
				}
				return tt.mockRec, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getMXData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getMXData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getMXData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestMXCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetMX) {
		t.Error("expected get_mx in capabilities")
	}
}
