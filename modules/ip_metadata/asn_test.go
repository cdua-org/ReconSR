package ip_metadata

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetASNDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetASN) {
		t.Error("expected get_asn in capabilities")
	}
}

func TestGetASNData(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Fatal("expected ASN results, got none")
	}

	foundOrigin := false
	foundPrefix := false

	for _, r := range res.Results {
		if strings.HasPrefix(r.Context, "ASN Origin") && r.Value == "AS64512" && r.Type == constants.TypeASN {
			foundOrigin = true
		}
		if r.Context == "BGP Prefix" && r.Value == "198.51.100.0/24" && r.Type == constants.TypeCIDR {
			foundPrefix = true
		}
	}

	if !foundOrigin {
		t.Error("expected at least one ASN Origin result")
	}
	if !foundPrefix {
		t.Error("expected at least one BGP Prefix result")
	}
}

func TestGetASNDataIPv6(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("2001:db8::1")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) == 0 {
		t.Error("expected ASN results for fake IPv6 target")
	}
}

func TestGetASNDataNoHost(t *testing.T) {
	setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
		return nil, nil
	})

	res := getASNData("192.0.2.1")
	if res.Error != nil {
		t.Errorf("expected no error for no ASN data, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(res.Results))
	}
}

func TestGetASNDataInvalidIP(t *testing.T) {
	res := getASNData("invalid-ip")
	if res.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestGetASNDataTimeout(t *testing.T) {
	setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
		return nil, context.DeadlineExceeded
	})

	res := getASNData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_ASN(t *testing.T) {
	mockASNLookup(t)

	res := getASNData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	requireUniqueLocalIDs(t, res.Results)
}

func TestGetASNInfoCoverage(t *testing.T) {
	tests := []struct {
		name     string
		asn      string
		expected string
		mockErr  error
		mockData []string
	}{
		{
			name:     "No AS prefix, error from query",
			asn:      "12345",
			expected: "",
			mockErr:  context.DeadlineExceeded,
			mockData: nil,
		},
		{
			name:     "No AS prefix, empty names",
			asn:      "12346",
			expected: "",
			mockErr:  nil,
			mockData: []string{},
		},
		{
			name:     "5 parts, empty company, non-empty country",
			asn:      "AS12347",
			expected: " (ZZ)",
			mockErr:  nil,
			mockData: []string{"ignored | ZZ | ignored | ignored | "},
		},
		{
			name:     "5 parts, empty company, empty country",
			asn:      "AS12348",
			expected: "",
			mockErr:  nil,
			mockData: []string{"ignored |  | ignored | ignored | "},
		},
		{
			name:     "2 parts, non-empty country",
			asn:      "AS12349",
			expected: " (ZZ)",
			mockErr:  nil,
			mockData: []string{"ignored | ZZ "},
		},
		{
			name:     "2 parts, empty country",
			asn:      "AS12350",
			expected: "",
			mockErr:  nil,
			mockData: []string{"ignored |  "},
		},
		{
			name:     "Less than 2 parts",
			asn:      "AS12351",
			expected: "",
			mockErr:  nil,
			mockData: []string{"ignoredonly"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setTXTQueryMock(t, func(_, _, _ string) ([]string, error) {
				return tt.mockData, tt.mockErr
			})
			res := getASNInfo(tt.asn)
			if res != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, res)
			}
		})
	}
}

func TestGetASNDataEdgeCases(t *testing.T) {
	setTXTQueryMock(t, func(_, _, queryType string) ([]string, error) {
		if queryType == "origin" {
			return []string{
				"AS64512 | 198.51.100.0/24",
				"invalid-no-pipe",
			}, nil
		}
		if queryType == "asn_info" {
			return []string{"ignored | ZZ | ignored | ignored | Example Network Operations LLC"}, nil
		}
		return nil, nil
	})

	res := getASNData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}

	expectedRaw := "AS64512 | 198.51.100.0/24\ninvalid-no-pipe"
	if res.RawData != expectedRaw {
		t.Errorf("expected raw data %q, got %q", expectedRaw, res.RawData)
	}

	foundOrigin := false
	for _, r := range res.Results {
		if r.Type == constants.TypeASN && r.Value == "AS64512" {
			foundOrigin = true
		}
	}
	if !foundOrigin {
		t.Error("expected to find AS64512 in results")
	}
}

func TestPerformTXTQuery(t *testing.T) {
	oldPlain := plainLookupTXT
	defer func() { plainLookupTXT = oldPlain }()

	oldRetry := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = oldRetry }()

	t.Run("Success", func(t *testing.T) {
		plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			return []string{"success record"}, nil
		}
		names, err := performTXTQuery("198.51.100.2", "test.query", "test")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(names) != 1 || names[0] != "success record" {
			t.Errorf("expected success record, got %v", names)
		}
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			return nil, &net.DNSError{IsNotFound: true}
		}
		names, err := performTXTQuery("198.51.100.2", "test.query", "test")
		if err != nil {
			t.Errorf("expected no error for NXDOMAIN, got %v", err)
		}
		if names != nil {
			t.Errorf("expected nil names for NXDOMAIN, got %v", names)
		}
	})

	t.Run("Retries and fails", func(t *testing.T) {
		calls := 0
		plainLookupTXT = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			calls++
			return nil, errors.New("timeout")
		}
		names, err := performTXTQuery("198.51.100.2", "test.query", "test")
		if err == nil {
			t.Error("expected error after retries, got nil")
		}
		if names != nil {
			t.Errorf("expected nil names, got %v", names)
		}
		if calls != resolver.MaxRetriesIPMeta {
			t.Errorf("expected %d calls, got %d", resolver.MaxRetriesIPMeta, calls)
		}
	})
}
