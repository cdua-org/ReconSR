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

func TestGetDKIMData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, target string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		if strings.HasPrefix(target, "google._domainkey.") {
			return []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD..."}, nil, nil
		}
		if strings.HasPrefix(target, "default._domainkey.") {
			return []string{"v=DKIM1; k=rsa; p=another_key..."}, nil, nil
		}
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDKIMData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res.Results))
	}
	if res.RawData == "" {
		t.Error("expected RawData to be populated")
	}
}

func TestGetDKIMData_Empty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDKIMData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetDKIMData_FallbackError(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		res, err := fallback(ctx, nil)
		if err != nil && !strings.Contains(err.Error(), "plain lookup dkim failed") {
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

	res := getDKIMData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Errorf("expected module to suppress lookup error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetDKIMData_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := getDKIMData(ctx, "example.com", modutil.NewLocalIDGenerator())

	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results due to context cancellation, got %d", len(res.Results))
	}
}

func TestGetDKIMData_FallbackSuccess(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, target string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		if strings.HasPrefix(target, "google._domainkey.") {
			res, err := fallback(ctx, nil)
			return res, nil, err
		}
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	oldPlain := plainLookupTXT
	plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
		return []string{"v=DKIM1; k=rsa; p=MIGf..."}, nil
	}
	defer func() { plainLookupTXT = oldPlain }()

	res := getDKIMData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result from fallback success, got %d", len(res.Results))
	}
}

func TestDKIMCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDKIM) {
		t.Error("expected get_dkim in capabilities")
	}
}
