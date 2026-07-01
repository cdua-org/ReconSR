package dnsutils

import (
	"reflect"
	"testing"
)

const (
	keyAlpn     = "alpn"
	keyPort     = "port"
	keyEch      = "ech"
	keyIPv4Hint = "ipv4hint"
	keyIPv6Hint = "ipv6hint"
	testAABB    = "aabb"
)

func TestParseSVCB(t *testing.T) {
	raw := "\\# 13 00 02 03 78 79 7a 00 00 FF 00 02 AA BB"
	priority, target, params, ok := ParseSVCB(raw)
	if !ok {
		t.Fatalf("ParseSVCB(wire) failed")
	}
	if priority != 2 || target != "xyz" || params["key255"] != testAABB {
		t.Errorf("ParseSVCB(wire) unexpected results: %v, %v, %v", priority, target, params)
	}
}

func TestParseSVCBPresentation(t *testing.T) {
	tests := []struct {
		wantParams   map[string]string
		name         string
		raw          string
		wantTarget   string
		wantPriority uint16
		wantOK       bool
	}{
		{
			map[string]string{keyAlpn: "h2,h3", keyIPv4Hint: "198.51.100.1"},
			"normal",
			"1 . alpn=h2,h3 ipv4hint=198.51.100.1",
			".",
			1,
			true,
		},
		{
			map[string]string{"baz": "h2,h3", keyEch: "abc"},
			"with quotes",
			"1 . baz=\"h2,h3\" ech=\"abc\"",
			".",
			1,
			true,
		},
		{
			nil,
			"too short",
			"1",
			"",
			0,
			false,
		},
		{
			nil,
			"invalid priority",
			"invalid . custom=h2",
			"",
			0,
			false,
		},
		{
			map[string]string{"mandatory": ""},
			"key without value",
			"1 example.com mandatory",
			"example.com",
			1,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority, target, params, ok := ParseSVCB(tt.raw)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok {
				if priority != tt.wantPriority {
					t.Errorf("priority = %v, want %v", priority, tt.wantPriority)
				}
				if target != tt.wantTarget {
					t.Errorf("target = %q, want %q", target, tt.wantTarget)
				}
				if len(params) != len(tt.wantParams) {
					t.Errorf("params len = %v, want %v", len(params), len(tt.wantParams))
				}
			}
		})
	}
}

func TestParseSVCBWire(t *testing.T) {
	tests := []struct {
		wantParams   map[string]string
		name         string
		raw          string
		wantTarget   string
		wantPriority uint16
		wantOK       bool
	}{
		{
			map[string]string{keyPort: "80"},
			"valid target domain and port",
			"\\# 13 00 02 03 61 62 63 00 00 03 00 02 00 50",
			"abc",
			2,
			true,
		},
		{
			nil,
			"too short to decode",
			"\\# 1 00",
			"",
			0,
			false,
		},
		{
			nil,
			"label out of bounds",
			"\\# 5 00 01 05 61 62",
			"",
			0,
			false,
		},
		{
			map[string]string{},
			"param out of bounds",
			"\\# 9 00 01 00 00 03 00 05 00 50",
			".",
			1,
			true,
		},
		{
			map[string]string{"key255": testAABB},
			"unknown param key",
			"\\# 9 00 01 00 00 FF 00 02 AA BB",
			".",
			1,
			true,
		},
		{
			map[string]string{keyAlpn: ""},
			"ALPN invalid length",
			"\\# 9 00 01 00 00 01 00 02 05 68",
			".",
			1,
			true,
		},
		{
			map[string]string{keyAlpn: "h3"},
			"ALPN valid",
			"\\# 10 00 01 00 00 01 00 03 02 68 33",
			".",
			1,
			true,
		},
		{
			map[string]string{keyPort: "50"},
			"Port invalid length",
			"\\# 8 00 01 00 00 03 00 01 50",
			".",
			1,
			true,
		},
		{
			map[string]string{keyIPv4Hint: "192.0.2.1"},
			"IPv4 invalid length skip loop",
			"\\# 11 00 01 00 00 04 00 04 c0 00 02 01",
			".",
			1,
			true,
		},
		{
			map[string]string{keyIPv6Hint: "2001:db8::1"},
			"IPv6 test",
			"\\# 23 00 01 00 00 06 00 10 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01",
			".",
			1,
			true,
		},
		{
			map[string]string{keyEch: testAABB},
			"ECH test",
			"\\# 9 00 01 00 00 05 00 02 AA BB",
			".",
			1,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority, target, params, ok := ParseSVCBWire(tt.raw)
			if ok != tt.wantOK {
				t.Errorf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok {
				if priority != tt.wantPriority {
					t.Errorf("priority = %v, want %v", priority, tt.wantPriority)
				}
				if target != tt.wantTarget {
					t.Errorf("target = %q, want %q", target, tt.wantTarget)
				}
				if !reflect.DeepEqual(params, tt.wantParams) {
					t.Errorf("params = %v, want %v", params, tt.wantParams)
				}
			}
		})
	}
}
