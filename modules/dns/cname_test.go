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

func TestGetCNAMEData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{"cdn.example.com."}, []byte("mocked cname bytes"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getCNAMEData(context.Background(), "example.org", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected CNAME results, got 0")
	}
	if res.RawData == "" {
		t.Error("expected RawData to be populated")
	}
}

func TestGetCNAMEDataEmpty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getCNAMEData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetCNAMEData_Error(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, target string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		if target == "example.net" {
			return nil, nil, errors.New("mock root error")
		}
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getCNAMEData(context.Background(), "example.net", modutil.NewLocalIDGenerator())

	if res.Error == nil {
		t.Error("expected error from root CNAME lookup")
	}
}

func TestBuildCNAMEResultInScopeSubdomain(t *testing.T) {
	result, ok := buildCNAMEResult("cdn.example.com.", "cname-scope.example.com", "CNAME Record", modutil.NewLocalIDGenerator())
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if !slices.Contains(result.Tags, constants.TagCNAME) {
		t.Fatalf("missing tag %q", constants.TagCNAME)
	}
	if result.Value != "cdn.example.com" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if result.OutOfScope {
		t.Fatal("expected in-scope CNAME to stay in scope")
	}
}

func TestBuildCNAMEResultOutOfScope(t *testing.T) {
	result, ok := buildCNAMEResult("vendor.foo.example.net.", "cname-oos.example.com", "CNAME Record", modutil.NewLocalIDGenerator())
	if !ok {
		t.Fatal("expected valid CNAME result")
	}
	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected subdomain type, got %q", result.Type)
	}
	if !slices.Contains(result.Tags, constants.TagCNAME) {
		t.Fatalf("missing tag %q", constants.TagCNAME)
	}
	if result.Value != "vendor.foo.example.net" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !result.OutOfScope {
		t.Fatal("expected external CNAME to be out of scope")
	}
}

func TestBuildCNAMEResultInvalid(t *testing.T) {
	_, ok := buildCNAMEResult("bad target", "cname-invalid.example.com", "CNAME Record", modutil.NewLocalIDGenerator())
	if ok {
		t.Fatal("expected invalid CNAME target to be skipped")
	}
}

func TestBuildCNAMEResultSelfReferential(t *testing.T) {
	_, ok := buildCNAMEResult("example.com.", "example.com", "CNAME Record", modutil.NewLocalIDGenerator())
	if ok {
		t.Fatal("expected self-referential CNAME to be skipped")
	}
}

func TestCNAMECapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetCNAME) {
		t.Error("expected get_cname in capabilities")
	}
}

func TestLookupCNAME_FallbackLogic(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(ctx context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		res, err := fallback(ctx, nil)
		if err != nil && !strings.Contains(err.Error(), "plain lookup cname failed") {
			t.Errorf("unexpected error from fallback: %v", err)
		}
		if res != nil {
			return res, nil, nil
		}
		return nil, nil, err
	}
	defer func() { resolveRecordFunc = oldResolve }()

	oldPlain := plainLookupCNAME
	plainLookupCNAME = func(_ context.Context, _ *net.Resolver, target string) (string, error) {
		if target == "error.example" {
			return "", errors.New("mock dial error")
		}
		if target == "cname.example" {
			return "target.example.", nil
		}
		return "", nil
	}
	defer func() { plainLookupCNAME = oldPlain }()

	_, _, err := lookupCNAME(context.Background(), "error.example")
	if err == nil {
		t.Error("expected error from lookupCNAME fallback")
	}

	cname, _, err := lookupCNAME(context.Background(), "cname.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cname != "target.example" {
		t.Errorf("expected target.example, got %q", cname)
	}

	cname, _, err = lookupCNAME(context.Background(), "nocname.example")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cname != "" {
		t.Errorf("expected empty cname, got %q", cname)
	}
}
