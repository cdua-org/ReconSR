package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestParseSVCBWire(t *testing.T) {
	raw := "\\# 61 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 c0 00 02 01 c6 33 64 02 00 06 00 20 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02"

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

	if v, exists := params["ipv4hint"]; !exists || !strings.Contains(v, "192.0.2.1") || !strings.Contains(v, "198.51.100.2") {
		t.Errorf("expected ipv4hint with reserved test IPv4 addresses, got %q", v)
	}

	if v, exists := params["ipv6hint"]; !exists || !strings.Contains(v, "2001:db8::1") {
		t.Errorf("expected ipv6hint with reserved test IPv6 addresses, got %q", v)
	}
}

func TestParseSVCBWirePassthrough(t *testing.T) {
	normal := "1 . alpn=h2,h3"
	_, _, _, ok := parseSVCBWire(normal)
	if ok {
		t.Error("expected ok=false for non-wire format")
	}
}

func TestGetSVCBDataEmpty(t *testing.T) {
	execution := getSVCBData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("svcb lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d SVCB/HTTPS results for example.com", len(execution.Results))
}

func TestGetSVCBDataNX(t *testing.T) {
	execution := getSVCBData(context.Background(), "nonexistent.domain.invalid")
	t.Logf("Found %d results for nonexistent domain", len(execution.Results))
}

func TestSVCBCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSVCB) {
		t.Error("expected get_svcb in capabilities")
	}
}
