package dns

import (
	"context"
	"errors"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func TestGetNSECData(t *testing.T) {
	originalQuery := queryDoHDnsFunc
	defer func() { queryDoHDnsFunc = originalQuery }()

	tests := []struct {
		name       string
		target     string
		mockFunc   func(context.Context, string, int) (*resolver.DoHResponse, []byte, error)
		wantPrefix string
		wantResCnt int
	}{
		{
			name:   "success_nsec",
			target: "alpha.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return &resolver.DoHResponse{
					Status: 0,
					Answer: []resolver.DoHDnsRecord{
						{Name: "alpha.example.com.", Type: 47, Data: "next.alpha.example.com. A NSEC"},
					},
				}, []byte("raw"), nil
			},
			wantResCnt: 6,
		},
		{
			name:   "success_nsec3",
			target: "beta.mango.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return &resolver.DoHResponse{
					Status: 0,
					Answer: []resolver.DoHDnsRecord{
						{Name: "hash.beta.mango.example.com.", Type: 50, Data: "1 0 10 salt next A NSEC"},
					},
				}, []byte("raw"), nil
			},
			wantResCnt: 9,
		},
		{
			name:   "nxdomain_authority",
			target: "gamma.example.org",
			mockFunc: func(_ context.Context, _ string, qtype int) (*resolver.DoHResponse, []byte, error) {
				if qtype == 1 {
					return &resolver.DoHResponse{
						Status: 3,
						Authority: []resolver.DoHDnsRecord{
							{Name: "gamma.example.org.", Type: 47, Data: "next.gamma.example.org. A NSEC"},
						},
					}, []byte("raw_nx"), nil
				}
				return nil, nil, errors.New("error")
			},
			wantResCnt: 2,
		},
		{
			name:   "nx_prefix_skip",
			target: "nx-prefix.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return nil, nil, nil
			},
			wantResCnt: 0,
		},
		{
			name:   "error_query",
			target: "error.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return nil, nil, errors.New("doh error")
			},
			wantResCnt: 0,
		},
		{
			name:   "nil_response",
			target: "lambda.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return nil, nil, nil
			},
			wantResCnt: 0,
		},
		{
			name:   "other_records_skipped",
			target: "delta.example.com",
			mockFunc: func(_ context.Context, _ string, _ int) (*resolver.DoHResponse, []byte, error) {
				return &resolver.DoHResponse{
					Status: 0,
					Answer: []resolver.DoHDnsRecord{
						{Name: "delta.example.com.", Type: 1, Data: "127.0.0.1"},
					},
				}, nil, nil
			},
			wantResCnt: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queryDoHDnsFunc = tt.mockFunc
			exec := getNSECData(context.Background(), tt.target, modutil.NewLocalIDGenerator())
			if len(exec.Results) != tt.wantResCnt {
				t.Errorf("getNSECData() results count = %d, want %d", len(exec.Results), tt.wantResCnt)
			}
		})
	}
}

func TestExtractNSECDomain(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		target   string
		nxTarget string
		want     bool
	}{
		{
			name:   "wildcard_root",
			raw:    "*.example.org.",
			target: "example.org",
			want:   true,
		},
		{
			name:   "wildcard_sub",
			raw:    "*.wild.wildnsec.example.com.",
			target: "wildnsec.example.com",
			want:   true,
		},
		{
			name:   "empty",
			raw:    "",
			target: "epsilon.example.com",
			want:   false,
		},
		{
			name:   "invalid_domain",
			raw:    "invalid!!domain",
			target: "zeta.example.com",
			want:   false,
		},
		{
			name:   "equals_target",
			raw:    "theta.example.com.",
			target: "theta.example.com",
			want:   false,
		},
		{
			name:     "equals_nxtarget",
			raw:      "nx-123.iota.example.com.",
			target:   "iota.example.com",
			nxTarget: "nx-123.iota.example.com",
			want:     false,
		},
		{
			name:   "valid_subdomain",
			raw:    "sub.kappa.example.com.",
			target: "kappa.example.com",
			want:   true,
		},
	}

	gen := modutil.NewLocalIDGenerator()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := extractNSECDomain(tt.raw, tt.target, tt.nxTarget, "Ctx", gen)
			if (res != nil) != tt.want {
				t.Errorf("extractNSECDomain() = %v, want %v", res, tt.want)
			}
		})
	}
}

func TestNSECCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetNSEC) {
		t.Error("expected get_nsec in capabilities")
	}
}

func TestParseNSECRecordSource(t *testing.T) {
	rec := resolver.DoHDnsRecord{
		Name: "current.example.com.",
		Data: "next.example.com. A AAAA RRSIG NSEC",
	}

	results := parseNSECRecord(rec, "example.com", "nx.example.com", "NSEC Context", modutil.NewLocalIDGenerator())

	if len(results) < 3 {
		t.Fatalf("expected at least 3 results, got %d", len(results))
	}

	currentSub := results[0]
	if currentSub.Type != constants.TypeSubdomain || currentSub.Value != "current.example.com" {
		t.Fatalf("expected current subdomain, got %s %s", currentSub.Type, currentSub.Value)
	}

	primary := results[1]
	if primary.Type != constants.TypeNSEC {
		t.Fatalf("expected primary result to be NSEC, got %s", primary.Type)
	}

	if primary.Value != "current.example.com NSEC next.example.com A AAAA RRSIG NSEC" {
		t.Errorf("expected normalized value without trailing dots, got %q", primary.Value)
	}

	if primary.Source == nil || primary.Source.Value != "current.example.com" {
		t.Errorf("expected NSEC property to have Source = current.example.com, got %v", primary.Source)
	}

	leakedSub := results[2]
	expectedSource := &schema.EntityRef{Type: primary.Type, Value: primary.Value}

	if leakedSub.Source == nil || leakedSub.Source.Type != expectedSource.Type || leakedSub.Source.Value != expectedSource.Value {
		t.Errorf("expected Source %v, got %v", expectedSource, leakedSub.Source)
	}
}

func TestParseNSEC3RecordSource(t *testing.T) {
	rec := resolver.DoHDnsRecord{
		Name: "0p9mhaveqvm6t7v8pon2iu430l8kcmpo.example.com.",
		Data: "1 0 10 AABBCCDD EEFF00112233 A RRSIG",
	}

	results := parseNSEC3Record(rec, "NSEC3 Context", modutil.NewLocalIDGenerator())

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	primary := results[0]
	if primary.Type != constants.TypeNSEC {
		t.Fatalf("expected primary result to be NSEC, got %s", primary.Type)
	}

	if primary.Value != "0p9mhaveqvm6t7v8pon2iu430l8kcmpo.example.com NSEC3 1 0 10 AABBCCDD EEFF00112233 A RRSIG" {
		t.Errorf("expected normalized NSEC3 value without trailing dots, got %q", primary.Value)
	}

	expectedSource := &schema.EntityRef{Type: primary.Type, Value: primary.Value}

	for i := 1; i < len(results); i++ {
		if results[i].Source == nil {
			t.Errorf("expected Source to be set for result %d", i)
		} else if results[i].Source.Type != expectedSource.Type || results[i].Source.Value != expectedSource.Value {
			t.Errorf("expected Source %v, got %v", expectedSource, results[i].Source)
		}
	}
}
