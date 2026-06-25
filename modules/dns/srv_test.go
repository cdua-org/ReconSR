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

func TestBuildSRVHostResult(t *testing.T) {
	srvRef := &schema.EntityRef{Type: constants.TypeSRV, Value: "10 50 5060 sip.example.com"}

	tests := []struct {
		name      string
		host      string
		target    string
		wantValue string
		wantType  string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "valid host gets normalized",
			host:      "SIP.SRV1.EXAMPLE.COM.",
			target:    "srv1.example.com",
			wantValue: "sip.srv1.example.com",
			wantType:  constants.TypeSubdomain,
			wantOK:    true,
			wantOOS:   false,
		},
		{
			name:      "out of scope host",
			host:      "sip.external.example.org",
			target:    "srv2.example.com",
			wantValue: "sip.external.example.org",
			wantType:  constants.TypeSubdomain,
			wantOK:    true,
			wantOOS:   true,
		},
		{
			name:      "invalid host is skipped",
			host:      "invalid_host",
			target:    "srv-invalid.example.com",
			wantValue: "",
			wantOK:    false,
			wantOOS:   false,
		},
		{
			name:      "self-referential host is skipped",
			host:      "srv-self.example.com",
			target:    "srv-self.example.com",
			wantValue: "",
			wantOK:    false,
			wantOOS:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := buildSRVHostResult(tt.host, tt.target, srvRef, modutil.NewLocalIDGenerator())
			if ok != tt.wantOK {
				t.Fatalf("buildSRVHostResult() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if result.Type != tt.wantType {
				t.Fatalf("buildSRVHostResult() type = %q, want %q", result.Type, tt.wantType)
			}
			if !slices.Contains(result.Tags, constants.TagSRV) {
				t.Fatalf("buildSRVHostResult() missing tag %q", constants.TagSRV)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("buildSRVHostResult() value = %q, want %q", result.Value, tt.wantValue)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("buildSRVHostResult() out_of_scope = %v, want %v", result.OutOfScope, tt.wantOOS)
			}
			if result.Source != srvRef {
				t.Fatalf("buildSRVHostResult() source = %+v, want %+v", result.Source, srvRef)
			}
		})
	}
}

func TestGetSRVData(t *testing.T) {
	origResolve := resolveRecordFunc
	defer func() { resolveRecordFunc = origResolve }()

	tests := []struct {
		mockFunc   func(context.Context, string, int, func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error)
		name       string
		domain     string
		wantResult int
	}{
		{
			name:   "srv_success",
			domain: "example.com",
			mockFunc: func(_ context.Context, target string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				if target == "_sip._tcp.example.com" {
					return []string{"10 20 5060 sip.example.com."}, []byte("raw"), nil
				}
				if target == "_sip._udp.example.com" {
					return []string{"invalid srv"}, []byte("raw"), nil
				}
				if target == "_http._tcp.example.com" {
					return []string{}, nil, nil
				}
				if target == "_ftp._tcp.example.com" {
					return []string{"10 20 21 example.com."}, []byte("raw"), nil
				}
				return nil, nil, errors.New("nxdomain")
			},
			wantResult: 3,
		},
		{
			name:   "srv_all_error",
			domain: "error.example",
			mockFunc: func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return nil, nil, errors.New("nxdomain")
			},
			wantResult: 0,
		},
		{
			name:   "srv_context_canceled",
			domain: "timeout.example",
			mockFunc: func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return nil, nil, nil
			},
			wantResult: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRecordFunc = tt.mockFunc

			ctx := context.Background()
			if tt.name == "srv_context_canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			exec := getSRVData(ctx, tt.domain, modutil.NewLocalIDGenerator())
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getSRVData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestSRVCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSRV) {
		t.Error("expected get_srv in capabilities")
	}
}

func TestMakeSRVFallback(t *testing.T) {
	origPlain := plainLookupSRV
	defer func() { plainLookupSRV = origPlain }()

	fallback := makeSRVFallback("fallback.srv.example.com")

	plainLookupSRV = func(_ context.Context, _ *net.Resolver, _, _, name string) (string, []*net.SRV, error) {
		if name == "error.srv.example.com" {
			return "", nil, errors.New("mock srv error")
		}
		return "cname", []*net.SRV{
			{Target: "server1.example.com.", Port: 5060, Priority: 10, Weight: 20},
		}, nil
	}

	res, err := fallback(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0] != "10 20 5060 server1.example.com." {
		t.Fatalf("unexpected formatted srv: %s", res[0])
	}

	fallbackErr := makeSRVFallback("error.srv.example.com")
	_, err = fallbackErr(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got none")
	}
}
