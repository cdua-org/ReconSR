package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseSVCBWire(t *testing.T) {
	// cloudflare.com HTTPS wire: priority=1, target=".", alpn=h3,h2, ipv4hint, ipv6hint
	raw := "\\# 61 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68 10 84 e5 68 10 85 e5 00 06 00 20 26 06 47 00 00 00 00 00 00 00 00 00 68 10 84 e5 26 06 47 00 00 00 00 00 00 00 00 00 68 10 85 e5"

	priority, target, params, ok := parseSVCBWire(raw)
	if !ok {
		t.Fatal("parseSVCBWire failed to decode")
	}

	if priority != 1 {
		t.Errorf("expected priority 1, got %d", priority)
	}

	if target != "." {
		t.Errorf("expected target '.', got %q", target)
	}

	if v, exists := params["alpn"]; !exists || !strings.Contains(v, "h3") || !strings.Contains(v, "h2") {
		t.Errorf("expected alpn to contain h3,h2, got %q", v)
	}

	if v, exists := params["ipv4hint"]; !exists || !strings.Contains(v, "104.16.") {
		t.Errorf("expected ipv4hint with 104.16.x.x, got %q", v)
	}

	if v, exists := params["ipv6hint"]; !exists || !strings.Contains(v, "2606:4700") {
		t.Errorf("expected ipv6hint with 2606:4700, got %q", v)
	}
}

func TestParseSVCBWirePassthrough(t *testing.T) {
	// Non-wire strings should return ok=false
	normal := "1 . alpn=h2,h3"
	_, _, _, ok := parseSVCBWire(normal)
	if ok {
		t.Error("expected ok=false for non-wire format")
	}
}

func TestGetSVCBDataEmpty(t *testing.T) {
	execution := getSVCBData("example.com")

	if execution.Error != nil {
		t.Logf("svcb lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d SVCB/HTTPS results for example.com", len(execution.Results))
}

func TestGetSVCBDataNX(t *testing.T) {
	execution := getSVCBData("nonexistent.domain.invalid")
	// Just verify it doesn't panic
	t.Logf("Found %d results for nonexistent domain", len(execution.Results))
}

func TestSVCBCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_svcb") {
		t.Error("expected get_svcb in capabilities")
	}
}
