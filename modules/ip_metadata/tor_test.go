package ip_metadata

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestGetTorDataSupported(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetTOR) {
		t.Error("expected get_tor in capabilities")
	}
}

func TestGetTorData(t *testing.T) {
	mockAQueryResponses(t, nil, nil)

	res := getTorData("198.51.100.2")
	if res.Error != nil {
		t.Fatalf("expected no error, got: %v", *res.Error)
	}
	if len(res.Results) != 0 {
		t.Error("expected fake IP not to be a Tor node")
	}
}

func TestGetTorDataKnown(t *testing.T) {
	resInvalid := getTorData("invalid-ip")
	if resInvalid.Error == nil {
		t.Error("expected error for invalid IP, got nil")
	}

	mockAQueryResponses(t, map[string][]string{
		".dnsel.torproject.org": {dnsblPositive},
	}, nil)

	resKnown := getTorData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}
	if len(resKnown.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resKnown.Results))
	}
	if resKnown.Results[0].Value != constants.TagTorExit {
		t.Errorf("expected %q, got %q", constants.TagTorExit, resKnown.Results[0].Value)
	}
}

func TestGetTorDataTimeout(t *testing.T) {
	mockAQueryResponses(t, nil, context.DeadlineExceeded)

	res := getTorData("198.51.100.2")
	if res.Error == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestModule_LocalIDChaining_TOR(t *testing.T) {
	mockAQueryResponses(t, map[string][]string{
		".torexit.dan.me.uk": {dnsblPositive},
	}, nil)

	resKnown := getTorData("203.0.113.25")
	if resKnown.Error != nil {
		t.Fatalf("expected no error, got: %v", *resKnown.Error)
	}

	requireUniqueLocalIDs(t, resKnown.Results)
}

func TestPerformAQuery(t *testing.T) {
	oldPlain := plainLookupHost
	defer func() { plainLookupHost = oldPlain }()

	oldRetry := resolver.RetryBaseDelay
	resolver.RetryBaseDelay = time.Millisecond
	defer func() { resolver.RetryBaseDelay = oldRetry }()

	t.Run("Success", func(t *testing.T) {
		plainLookupHost = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		}
		ips, err := performAQuery("198.51.100.2", "test.query", "test")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(ips) != 1 || ips[0] != "192.0.2.1" {
			t.Errorf("expected 192.0.2.1, got %v", ips)
		}
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		plainLookupHost = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		ips, err := performAQuery("198.51.100.2", "nxdomain.query", "test")
		if err != nil {
			t.Errorf("expected no error for nxdomain, got %v", err)
		}
		if len(ips) != 0 {
			t.Errorf("expected nil ips, got %v", ips)
		}
	})

	t.Run("Retries and fails", func(t *testing.T) {
		plainLookupHost = func(_ context.Context, _ *net.Resolver, _ string) ([]string, error) {
			return nil, context.DeadlineExceeded
		}
		ips, err := performAQuery("198.51.100.2", "timeout.query", "test")
		if err == nil {
			t.Error("expected timeout error, got nil")
		}
		if len(ips) != 0 {
			t.Errorf("expected nil ips, got %v", ips)
		}
	})
}
