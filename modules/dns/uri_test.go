package dns

import (
	"slices"
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	// \# 43 000a000168747470733a2f2f6f73696e742e6578616d706c652e636f6d2f746573742d656e64706f696e74
	// = priority 10, weight 1, https://osint.example.com/test-endpoint
	raw := "\\# 43 000a000168747470733a2f2f6f73696e742e6578616d706c652e636f6d2f746573742d656e64706f696e74"
	expected := `10 1 "https://osint.example.com/test-endpoint"`

	parsed := parseURI(raw)
	if parsed != expected {
		t.Errorf("parseURI() = %q, want %q", parsed, expected)
	}

	// Already-decoded string should pass through unchanged
	normal := `10 1 "https://example.com"`
	if parseURI(normal) != normal {
		t.Errorf("expected already-decoded string to remain unmodified")
	}
}

func TestGetURIDataEmpty(t *testing.T) {
	execution := getURIData("example.com")

	if execution.Error != nil {
		t.Logf("uri lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Found URI record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetURIDataNX(t *testing.T) {
	execution := getURIData("nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("uri lookup failed: %v", *execution.Error)
	}
}

func TestURICapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_uri") {
		t.Error("expected get_uri in capabilities")
	}
}
