package dns

import (
	"context"
	"slices"
	"testing"
)

func TestGetNSDataEmpty(t *testing.T) {
	execution := getNSData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("ns lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetNSData(t *testing.T) {
	res := getNSData(context.Background(), "example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Error("expected at least one NS for example.com")
	case res.Results[0].Type != "ns":
		t.Errorf("unexpected type: %s", res.Results[0].Type)
	}
}

func TestBuildNSResultInScope(t *testing.T) {
	result, ok := buildNSResult("Ns1.Example.com.", "example.com")
	if !ok {
		t.Fatal("expected valid NS result")
	}
	if result.Type != "ns" {
		t.Fatalf("expected ns type, got %q", result.Type)
	}
	if result.Value != "ns1.example.com" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if result.Context != "NS Record" {
		t.Fatalf("unexpected context: got %q", result.Context)
	}
	if result.OutOfScope {
		t.Fatal("expected in-scope NS to stay in scope")
	}
}

func TestBuildNSResultOutOfScope(t *testing.T) {
	result, ok := buildNSResult("ns1.vendor.net.", "example.com")
	if !ok {
		t.Fatal("expected valid NS result")
	}
	if result.Value != "ns1.vendor.net" {
		t.Fatalf("expected normalized value, got %q", result.Value)
	}
	if !result.OutOfScope {
		t.Fatal("expected external NS to be out of scope")
	}
}

func TestBuildNSResultInvalid(t *testing.T) {
	_, ok := buildNSResult("bad target", "example.com")
	if ok {
		t.Fatal("expected invalid NS target to be skipped")
	}
}

func TestNSCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_ns") {
		t.Error("expected get_ns in capabilities")
	}
}
