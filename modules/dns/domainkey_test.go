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

func TestGetDomainKeyDataEmpty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	execution := getDomainKeyData(context.Background(), "empty.example", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Fatalf("unexpected error: %v", *execution.Error)
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetDomainKeyData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		_, err := fallback(context.Background(), net.DefaultResolver)
		if err == nil {
			t.Log("fallback unexpectedly succeeded")
		}

		return []string{
			"\"v=DKIM1; k=rsa; p=MIGfMA0GCSq...\"",
		}, []byte("mocked raw data"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDomainKeyData(context.Background(), "test.example", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.RawData == "" {
		t.Error("expected RawData to be set")
	}
}

func TestGetDomainKeyData_Error(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, errors.New("mock domainkey error")
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDomainKeyData(context.Background(), "error.example", modutil.NewLocalIDGenerator())

	if res.Error == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetDomainKeyData_FallbackSuccess(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		res, err := fallback(ctx, nil)
		return res, nil, err
	}
	defer func() { resolveRecordFunc = oldResolve }()

	oldPlain := plainLookupTXT
	plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
		return []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSq...Success"}, nil
	}
	defer func() { plainLookupTXT = oldPlain }()

	res := getDomainKeyData(context.Background(), "success.example", modutil.NewLocalIDGenerator())
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected results from fallback")
	}
}

func TestDomainKeyCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDomainKey) {
		t.Error("expected get_domainkey in capabilities")
	}
}
