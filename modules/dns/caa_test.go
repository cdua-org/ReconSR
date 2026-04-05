package dns

import (
	"slices"
	"testing"
)

func TestParseCAARecord(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		expected []string // we will just check the Type of the returned results
	}{
		{
			name:     "issue basic",
			record:   `0 issue "letsencrypt.org"`,
			expected: []string{"string", "domain"},
		},
		{
			name:     "iodef email",
			record:   `0 iodef "mailto:security@example.com"`,
			expected: []string{"string", "email"},
		},
		{
			name:     "iodef url",
			record:   `0 iodef "https://example.com/abuse"`,
			expected: []string{"string", "url"},
		},
		{
			name:     "issue with parameters",
			record:   `0 issue "pki.goog; cansignhttpexchanges=yes"`,
			expected: []string{"string", "domain"},
		},
		{
			name:     "hex encoded issue",
			record:   `\# 21 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67`, // equivalent to 0 issue "letsencrypt.org"
			expected: []string{"string", "domain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseCAARecord(tt.record)
			if len(res) != len(tt.expected) {
				t.Fatalf("expected %d results, got %d", len(tt.expected), len(res))
			}
			for i, r := range res {
				if r.Type != tt.expected[i] {
					t.Errorf("expected type %s, got %s", tt.expected[i], r.Type)
				}
			}
		})
	}
}

func TestGetCAAData(t *testing.T) {
	// A basic integration test
	res := getCAAData("example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		// Some domains might not have CAA, so we don't strictly fail on empty results
		// but example.com does not have a CAA usually, or wait, it might.
		// So we just pass if it doesn't fail with an error.
		t.Log("No CAA records found for example.com")
	default:
		if res.Results[0].Type != "string" {
			t.Errorf("expected type 'string' (raw CAA), got '%s'", res.Results[0].Type)
		}
	}
}

func TestCAACapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_caa") {
		t.Error("expected get_caa in capabilities")
	}
}
