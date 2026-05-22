package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestGetNSDataEmpty(t *testing.T) {
	execution := getNSData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("ns lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetNSData(t *testing.T) {
	res := getNSData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one NS for example.com")
	case !slices.Contains(res.Results[0].Tags, constants.TagNS):
		t.Errorf("expected ns tag, got %v", res.Results[0].Tags)
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
