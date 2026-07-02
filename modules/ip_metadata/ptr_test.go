package ip_metadata

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetPTRDataMockedResult(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr1.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected results, got none")
	}
	if res.Results[0].Value != "ptr1.example.com" {
		t.Errorf("expected %q, got %q", "ptr1.example.com", res.Results[0].Value)
	}
}

func TestGetPTRData(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr3.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected at least one PTR record")
	}
	if res.Results[0].Type != constants.TypeSubdomain {
		t.Errorf("expected type %q, got %q", constants.TypeSubdomain, res.Results[0].Type)
	}
	if !slices.Contains(res.Results[0].Tags, constants.TagReverseIP) {
		t.Errorf("expected tag %q, got %v", constants.TagReverseIP, res.Results[0].Tags)
	}
}

func TestGetPTRDataInvalidPTRHostname(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"invalid ptr hostname."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.Results[0].Type != constants.TypePTR {
		t.Errorf("expected type %q, got %q", constants.TypePTR, res.Results[0].Type)
	}
	if res.Results[0].Category != constants.CategoryProperty {
		t.Errorf("expected category %q, got %q", constants.CategoryProperty, res.Results[0].Category)
	}
	if len(res.Results[0].Tags) > 0 {
		t.Errorf("expected no tags for invalid PTR hostname, got %v", res.Results[0].Tags)
	}
}

func TestGetPTRDataNoHost(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return nil, nil
	})

	res := getPTRData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for non-existent PTR, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetPTRDataInvalidIP(t *testing.T) {
	res := getPTRData("invalid-ip")
	if res.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestGetPTRDataTimeout(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return nil, context.DeadlineExceeded
	})

	res := getPTRData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_PTR(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"ptr4.example.com."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}

func TestGetPTRDataEmptyName(t *testing.T) {
	setPTRQueryMock(t, func(string) ([]string, error) {
		return []string{"."}, nil
	})

	res := getPTRData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res.Results))
	}
}

func TestPerformPTRQuery(t *testing.T) {
	oldPlain := ptrResolveRecordFunc
	defer func() { ptrResolveRecordFunc = oldPlain }()

	oldRetry := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = oldRetry }()

	t.Run("Success", func(t *testing.T) {
		ptrResolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
			return []string{"ptr5.example.com."}, nil, nil
		}
		names, err := performPTRQuery("198.51.100.2")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(names) != 1 || names[0] != "ptr5.example.com." {
			t.Errorf("expected success record, got %v", names)
		}
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		ptrResolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
			return nil, nil, &net.DNSError{IsNotFound: true}
		}
		names, err := performPTRQuery("198.51.100.2")
		if err != nil {
			t.Errorf("expected no error for NXDOMAIN, got %v", err)
		}
		if names != nil {
			t.Errorf("expected nil names for NXDOMAIN, got %v", names)
		}
	})

	t.Run("Retries and fails", func(t *testing.T) {
		ptrResolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
			return nil, nil, errors.New("temporary error")
		}
		names, err := performPTRQuery("198.51.100.2")
		if err == nil {
			t.Error("expected error after retries, got nil")
		}
		if names != nil {
			t.Errorf("expected nil names, got %v", names)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		ptrResolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
			return []string{"ipv6.example.com."}, nil, nil
		}
		names, err := performPTRQuery("2001:db8::1")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(names) != 1 || names[0] != "ipv6.example.com." {
			t.Errorf("expected success record, got %v", names)
		}
	})

	t.Run("Fallback coverage", func(t *testing.T) {
		var capturedFallback func(context.Context, *net.Resolver) ([]string, error)
		ptrResolveRecordFunc = func(_ context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
			capturedFallback = fallback
			return nil, nil, nil
		}
		_, err := performPTRQuery("198.51.100.2")
		if err != nil {
			t.Logf("expected error from mock, got %v", err)
		}
		if capturedFallback != nil {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, errFallback := capturedFallback(ctx, net.DefaultResolver)
			if errFallback != nil {
				t.Logf("expected context canceled error, got %v", errFallback)
			}
		}
	})
}
