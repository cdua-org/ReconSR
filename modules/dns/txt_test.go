package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetTXTData(t *testing.T) {
	origResolve := resolveRecordFunc
	origPlain := plainLookupTXT
	defer func() {
		resolveRecordFunc = origResolve
		plainLookupTXT = origPlain
	}()

	tests := []struct {
		name         string
		domain       string
		mockErr      error
		fallbackErr  error
		mockRec      []string
		mockRaw      []byte
		fallbackTXTs []string
		wantResult   int
		callFallback bool
		wantErr      bool
	}{
		{
			name:         "txt_success_records",
			domain:       "cherry-txt.example",
			mockErr:      nil,
			mockRec:      []string{"\"v=spf1 -all\"", "\"general txt record\"", ""},
			mockRaw:      []byte("raw"),
			callFallback: false,
			wantResult:   2,
			wantErr:      false,
		},
		{
			name:         "txt_resolve_error",
			domain:       "berry-txt.example",
			mockErr:      errors.New("mock dns error"),
			callFallback: false,
			wantResult:   0,
			wantErr:      true,
		},
		{
			name:         "txt_fallback_success",
			domain:       "date.example",
			mockErr:      nil,
			callFallback: true,
			fallbackErr:  nil,
			fallbackTXTs: []string{"v=spf1 include:spf.example.com ~all"},
			wantResult:   2,
			wantErr:      false,
		},
		{
			name:         "txt_fallback_error",
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
			plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
				return tt.fallbackTXTs, tt.fallbackErr
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
			exec := getTXTData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getTXTData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getTXTData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestBuildSPFEntityResult_Default(t *testing.T) {
	ent := dnsutils.SPFEntity{Kind: 999}
	_, ok := buildSPFEntityResult(nil, ent, "example.com", modutil.NewLocalIDGenerator())
	if ok {
		t.Error("expected false for unknown kind")
	}
}

func TestBuildSPFIPResult_Invalid(t *testing.T) {
	ent := dnsutils.SPFEntity{Kind: dnsutils.SPFEntityIP4, Value: "invalid-ip"}
	_, ok := buildSPFIPResult(nil, ent, modutil.NewLocalIDGenerator())
	if ok {
		t.Error("expected false for invalid IP")
	}
}

func TestBuildSPFDomainResult_Invalid(t *testing.T) {
	ent := dnsutils.SPFEntity{Kind: dnsutils.SPFEntityDomain, Value: "invalid domain!"}
	_, ok := buildSPFDomainResult(nil, ent, "example.com", modutil.NewLocalIDGenerator())
	if ok {
		t.Error("expected false for invalid domain")
	}
}

func TestTXTCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetTXT) {
		t.Error("expected get_txt in capabilities")
	}
}

func TestGetTXTData_LocalIDChaining(t *testing.T) {
	exec := getTXTData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if exec.Error != nil {
		t.Fatalf("Expected no error, got: %v", *exec.Error)
	}
	if len(exec.Results) < 2 {
		t.Skip("Expected multiple results to verify chaining, skipping test")
	}

	for i, res := range exec.Results {
		expectedID := i + 1
		if res.LocalID != expectedID {
			t.Errorf("Expected LocalID %d at index %d, got %d (Type: %s, Value: %s)", expectedID, i, res.LocalID, res.Type, res.Value)
		}
	}
}

func TestBuildSPFEntityResults(t *testing.T) {
	spf := "v=spf1 ip4:198.51.100.10 ip6:2001:db8::1 include:spf.example.net a:web.example.org mx:relay.example.edu -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "example.com", modutil.NewLocalIDGenerator())

	requireSPFResult(t, results, constants.TypeIPv4, "198.51.100.10", "SPF ip4", false)
	requireSPFResult(t, results, constants.TypeIPv6, "2001:db8::1", "SPF ip6", false)
	requireSPFResult(t, results, constants.TypeSubdomain, "spf.example.net", "SPF include", true)
	requireSPFResult(t, results, constants.TypeSubdomain, "web.example.org", "SPF a", true)
	requireSPFResult(t, results, constants.TypeSubdomain, "relay.example.edu", "SPF mx", true)

	for _, res := range results {
		if !slices.Contains(res.Tags, constants.TagSPF) {
			t.Fatalf("expected tag %q on result %q, got %v", constants.TagSPF, res.Value, res.Tags)
		}
		if res.Source == nil || res.Source.Type != constants.TypeSPF {
			t.Fatalf("expected source linked to SPF record, got %+v", res.Source)
		}
	}
}

func TestBuildSPFEntityResultsSelfReferentialSkipped(t *testing.T) {
	spf := "v=spf1 include:samehost.example.com redirect=samehost.example.com -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "samehost.example.com", modutil.NewLocalIDGenerator())

	for _, res := range results {
		if res.Value == "samehost.example.com" {
			t.Fatal("expected self-referential SPF domain to NOT be emitted")
		}
	}
}

func TestBuildSPFEntityResultsEmptySPF(t *testing.T) {
	spf := "v=spf1 -all"
	source := &schema.EntityRef{Type: constants.TypeSPF, Value: spf}

	results := buildSPFEntityResults(source, spf, "example.com", modutil.NewLocalIDGenerator())
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty SPF, got %d", len(results))
	}
}

func requireSPFResult(t *testing.T, results []schema.ModuleResult, wantType, wantValue, wantContext string, wantOOS bool) {
	t.Helper()

	for _, res := range results {
		if res.Type == wantType && res.Value == wantValue {
			if res.Context != wantContext {
				t.Fatalf("result %q context = %q, want %q", wantValue, res.Context, wantContext)
			}
			if res.OutOfScope != wantOOS {
				t.Fatalf("result %q out_of_scope = %v, want %v", wantValue, res.OutOfScope, wantOOS)
			}
			return
		}
	}

	t.Fatalf("expected SPF result type=%q value=%q not found", wantType, wantValue)
}
