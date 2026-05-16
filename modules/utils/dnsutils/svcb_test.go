package dnsutils

import (
	"strings"
	"testing"
)

func TestParseSVCBWire(t *testing.T) {
	raw := "\\# 61 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 c0 00 02 01 c6 33 64 02 00 06 00 20 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02"

	priority, target, params, ok := ParseSVCBWire(raw)
	if !ok {
		t.Fatal("ParseSVCBWire failed to decode")
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

func TestParseSVCBPresentation(t *testing.T) {
	normal := "1 . alpn=h2,h3 ipv4hint=198.51.100.1"
	priority, target, params, ok := ParseSVCB(normal)
	if !ok {
		t.Fatal("ParseSVCB failed for presentation format")
	}
	if priority != 1 {
		t.Errorf("expected priority 1, got %d", priority)
	}
	if target != "." {
		t.Errorf("expected target '.', got %q", target)
	}
	if v, exists := params["alpn"]; !exists || v != "h2,h3" {
		t.Errorf("expected alpn=h2,h3, got %q", v)
	}
	if v, exists := params["ipv4hint"]; !exists || v != "198.51.100.1" {
		t.Errorf("expected ipv4hint=198.51.100.1, got %q", v)
	}
}
