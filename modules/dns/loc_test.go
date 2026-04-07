package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseLOC(t *testing.T) {
	// 48 51 29.600 N 2 17 40.200 E 300.00m 10m 10m 10m
	// User example wire format: \# 16 001313138a7bdcc0807e0a6800990bb0
	raw := "\\# 16 001313138a7bdcc0807e0a6800990bb0"
	expected := "48 51 29.600 N 2 17 40.200 E 300.00m 10.00m 10.00m 10.00m"

	parsed := parseLOC(raw)
	if parsed != expected {
		t.Errorf("parseLOC() = %q, want %q", parsed, expected)
	}

	// Unrelated string formatting
	normal := "48 51 29.600 N 2 17 40.200 E 300.00m 10m"
	if parseLOC(normal) != normal {
		t.Errorf("expected string to remain unmodified")
	}
}

func TestGetLOCDataEmpty(t *testing.T) {
	// example.com very rarely has a LOC record
	execution := getLOCData("example.com")

	if execution.Error != nil {
		t.Logf("loc lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Unexpectedly found LOC record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetLOCDataNX(t *testing.T) {
	execution := getLOCData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") { // Status 3 is NXDOMAIN
		t.Logf("loc lookup failed: %v", *execution.Error)
	}
}

func TestLOCCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_loc") {
		t.Error("expected get_loc in capabilities")
	}
}
