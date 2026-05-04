package dns

import (
	"context"
	"slices"
	"testing"
)

func TestGetTXTDataEmpty(t *testing.T) {
	execution := getTXTData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("txt lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetTXTData(t *testing.T) {
	res := getTXTData(context.Background(), "example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else {
		t.Logf("TXT/SPF records found (or none): %d", len(res.Results))
	}
}

func TestTXTCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_txt") {
		t.Error("expected get_txt in capabilities")
	}
}
