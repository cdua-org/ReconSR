package domainsbycerts

import (
	"testing"
	"time"
)

const testTypeDomain = "domain"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Example.COM", "example.com"},
		{"*.example.com", "example.com"},
		{"  A.example.com  ", "a.example.com"},
		{"*.SUB.example.com", "sub.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := normalizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsValidSubdomain(t *testing.T) {
	tests := []struct {
		domain   string
		target   string
		expected bool
	}{
		{"a.example.com", "example.com", true},
		{"sub.a.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"notexample.com", "example.com", false},
		{"sub.notexample.com", "example.com", false},
		{"", "example.com", false},
	}

	for _, tt := range tests {
		got := isValidSubdomain(tt.domain, tt.target)
		if got != tt.expected {
			t.Errorf("isValidSubdomain(%q, %q) = %v, want %v", tt.domain, tt.target, got, tt.expected)
		}
	}
}

func TestParseCertTimestamp(t *testing.T) {
	tests := []struct {
		input  string
		isZero bool
	}{
		{"2026-05-06T12:07:45", false},       // crt.sh format (no timezone)
		{"2026-05-06T12:07:45Z", false},      // RFC3339 UTC
		{"2026-05-06T12:07:45+03:00", false}, // RFC3339 with offset
		{"2026-05-06 12:07:45", false},       // Certspotter date format
		{"", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		got := parseCertTimestamp(tt.input)
		if got.IsZero() != tt.isZero {
			t.Errorf("parseCertTimestamp(%q).IsZero() = %v, want %v", tt.input, got.IsZero(), tt.isZero)
		}
	}
}

func TestClassifyDomains(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	domains := []domainSource{
		{domain: "example.com", source: "crt.sh", NotAfter: future},
		{domain: "example.com", source: "crt.sh", NotAfter: past},
		{domain: "*.example.com", source: "crt.sh", NotAfter: future},
		{domain: "a.example.com", source: "crt.sh", NotAfter: future},
		{domain: "B.example.com", source: "Certspotter", NotAfter: past},
		{domain: "a.example.com", source: "Certspotter", NotAfter: past},
		{domain: "notexample.com", source: "crt.sh", NotAfter: future},
		{domain: "sub.notexample.com", source: "crt.sh", NotAfter: future},
		{domain: "deep.sub.example.com", source: "crt.sh", NotAfter: future},
	}

	classified := classifyDomains(domains, "example.com")

	if classified.targetMaxExpiry.Before(now) {
		t.Error("targetMaxExpiry should be in the future")
	}

	// Valid subdomains: a.example.com, b.example.com, deep.sub.example.com
	if len(classified.subdomains) != 3 {
		t.Errorf("expected 3 unique subdomains, got %d", len(classified.subdomains))
	}

	if na, ok := classified.subdomains["a.example.com"]; !ok || !na.Equal(future) {
		t.Errorf("a.example.com: expected future timestamp, got %v", na)
	}

	if na, ok := classified.subdomains["b.example.com"]; !ok || !na.Equal(past) {
		t.Errorf("b.example.com: expected past timestamp, got %v", na)
	}

	if _, ok := classified.subdomains["notexample.com"]; ok {
		t.Error("notexample.com should not be classified as a subdomain")
	}
}

func TestFormatResults_GhostFiltering(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedDomains{
		subdomains: map[string]time.Time{
			"active.example.com":  future,
			"expired.example.com": past,
			"unknown.example.com": {},
		},
		subdomainSources: map[string]string{
			"active.example.com":  "crt.sh",
			"expired.example.com": "crt.sh",
			"unknown.example.com": "crt.sh",
		},
		targetMaxExpiry: future,
		targetSource:    "crt.sh",
	}

	results := formatResults(classified, "example.com", false)

	var domainResults, ghostResults int
	for _, r := range results {
		if r.Type == testTypeDomain {
			domainResults++
		}
		if r.Context == "Ghost subdomains" {
			ghostResults++
		}
	}

	// active + unknown + target = 3 domains; expired goes to ghost
	if domainResults != 3 {
		t.Errorf("with ghost filtering: expected 3 domain results, got %d", domainResults)
	}
	if ghostResults != 1 {
		t.Errorf("with ghost filtering: expected 1 ghost result, got %d", ghostResults)
	}
}

func TestFormatResults_DisableGhostDomains(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedDomains{
		subdomains: map[string]time.Time{
			"active.example.com":  future,
			"expired.example.com": past,
		},
		subdomainSources: map[string]string{
			"active.example.com":  "crt.sh",
			"expired.example.com": "crt.sh",
		},
		targetMaxExpiry: future,
		targetSource:    "crt.sh",
	}

	results := formatResults(classified, "example.com", true)

	var domainResults, ghostResults int
	for _, r := range results {
		if r.Type == testTypeDomain {
			domainResults++
		}
		if r.Context == "Ghost subdomains" {
			ghostResults++
		}
	}

	// All domains emitted: active + expired + target = 3; no ghost grouping
	if domainResults != 3 {
		t.Errorf("with ghost disabled: expected 3 domain results, got %d", domainResults)
	}
	if ghostResults != 0 {
		t.Errorf("with ghost disabled: expected 0 ghost results, got %d", ghostResults)
	}
}

func TestFormatResults_ExpiredTarget(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)

	classified := classifiedDomains{
		subdomains:       make(map[string]time.Time),
		subdomainSources: make(map[string]string),
		targetMaxExpiry:  past,
		targetSource:     "crt.sh",
	}

	results := formatResults(classified, "example.com", false)

	for _, r := range results {
		if r.Type == testTypeDomain && r.Value == "example.com" {
			t.Error("expired target should not appear in results")
		}
	}
}
