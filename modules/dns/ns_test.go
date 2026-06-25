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

func TestGetNSData(t *testing.T) {
	origResolve := resolveRecordFunc
	origPlain := plainLookupNS
	defer func() {
		resolveRecordFunc = origResolve
		plainLookupNS = origPlain
	}()

	tests := []struct {
		name         string
		domain       string
		mockErr      error
		fallbackErr  error
		mockRec      []string
		mockRaw      []byte
		fallbackNSs  []*net.NS
		wantResult   int
		callFallback bool
		wantErr      bool
	}{
		{
			name:         "ns_success_records",
			domain:       "cherry-ns.example",
			mockErr:      nil,
			mockRec:      []string{"ns1.example.com.", "ns2.example.com.", "invalid_ns"},
			mockRaw:      []byte("raw"),
			callFallback: false,
			wantResult:   2,
			wantErr:      false,
		},
		{
			name:         "ns_success_empty",
			domain:       "empty-ns.example",
			mockErr:      nil,
			mockRec:      []string{"invalid_only"},
			mockRaw:      []byte("raw"),
			callFallback: false,
			wantResult:   0,
			wantErr:      false,
		},
		{
			name:         "ns_resolve_error",
			domain:       "berry-ns.example",
			mockErr:      errors.New("mock dns error"),
			callFallback: false,
			wantResult:   0,
			wantErr:      true,
		},
		{
			name:         "ns_fallback_success",
			domain:       "date-ns.example",
			mockErr:      nil,
			callFallback: true,
			fallbackErr:  nil,
			fallbackNSs: []*net.NS{
				{Host: "fallback-ns.example.com."},
			},
			wantResult: 1,
			wantErr:    false,
		},
		{
			name:         "ns_fallback_error",
			domain:       "fig-ns.example",
			mockErr:      errors.New("mock dns error"),
			callFallback: true,
			fallbackErr:  errors.New("fallback failed"),
			wantResult:   0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainLookupNS = func(_ context.Context, _ *net.Resolver, _ string) ([]*net.NS, error) {
				return tt.fallbackNSs, tt.fallbackErr
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
			exec := getNSData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getNSData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getNSData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestBuildNSResultInScope(t *testing.T) {
	result, ok := buildNSResult("ns1.example.com.", "example.com", modutil.NewLocalIDGenerator())
	if !ok {
		t.Fatal("expected valid NS result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if result.Value != "ns1.example.com" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !slices.Contains(result.Tags, constants.TagNS) {
		t.Fatalf("expected ns tag, got %v", result.Tags)
	}
	if result.OutOfScope {
		t.Fatal("expected in-scope NS to stay in scope")
	}
}

func TestBuildNSResultOutOfScope(t *testing.T) {
	result, ok := buildNSResult("ns1.example.net.", "example.com", modutil.NewLocalIDGenerator())
	if !ok {
		t.Fatal("expected valid NS result")
	}
	if result.Value != "ns1.example.net" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !result.OutOfScope {
		t.Fatal("expected external NS to be out of scope")
	}
}

func TestBuildNSResultInvalid(t *testing.T) {
	_, ok := buildNSResult("bad target", "example.com", modutil.NewLocalIDGenerator())
	if ok {
		t.Fatal("expected invalid NS target to be skipped")
	}
}

func TestBuildNSResultSelfReferential(t *testing.T) {
	_, ok := buildNSResult("example.com.", "example.com", modutil.NewLocalIDGenerator())
	if ok {
		t.Fatal("expected self-referential NS to be skipped")
	}
}

func TestBuildNSResultEmpty(t *testing.T) {
	_, ok := buildNSResult(" . ", "example.com", modutil.NewLocalIDGenerator())
	if ok {
		t.Fatal("expected empty NS to be skipped")
	}
}

func TestNSCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetNS) {
		t.Error("expected get_ns in capabilities")
	}
}
