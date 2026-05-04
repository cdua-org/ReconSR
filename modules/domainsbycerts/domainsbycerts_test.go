package domainsbycerts

import (
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Example.COM", "example.com"},
		{"*.example.com", "*.example.com"},
		{"  A.example.com  ", "a.example.com"},
		{"*.SUB.example.com", "*.sub.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		got := normalizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestMatchesTargetIdentity(t *testing.T) {
	tests := []struct {
		value    string
		target   string
		expected bool
	}{
		{"a.example.com", "example.com", true},
		{"*.example.com", "example.com", true},
		{"user@example.com", "example.com", true},
		{"dove@alum.mit.edu", "mit.edu", true},
		{"example.com", "example.com", true},
		{"sub.notexample.com", "example.com", false},
		{"user@gmail.com", "example.com", false},
		{"", "example.com", false},
	}

	for _, tt := range tests {
		got := matchesTargetIdentity(tt.value, tt.target)
		if got != tt.expected {
			t.Errorf("matchesTargetIdentity(%q, %q) = %v, want %v", tt.value, tt.target, got, tt.expected)
		}
	}
}

func TestClassifyMatchedIdentity(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		target       string
		wantKind     string
		wantValue    string
		wantAccepted bool
	}{
		{
			name:         "target domain",
			value:        "example.com",
			target:       "example.com",
			wantKind:     identityKindTarget,
			wantValue:    "example.com",
			wantAccepted: true,
		},
		{
			name:         "wildcard subdomain",
			value:        "*.example.com",
			target:       "example.com",
			wantKind:     resultTypeSubdomain,
			wantValue:    "*.example.com",
			wantAccepted: true,
		},
		{
			name:         "regular subdomain",
			value:        "Deep.Sub.Example.com",
			target:       "example.com",
			wantKind:     resultTypeSubdomain,
			wantValue:    "deep.sub.example.com",
			wantAccepted: true,
		},
		{
			name:         "valid email",
			value:        "dove@alum.mit.edu",
			target:       "mit.edu",
			wantKind:     resultTypeEmail,
			wantValue:    "dove@alum.mit.edu",
			wantAccepted: true,
		},
		{
			name:         "invalid email extra is rejected",
			value:        "\"dove\"@alum.mit.edu",
			target:       "mit.edu",
			wantAccepted: false,
		},
		{
			name:         "invalid domain is rejected",
			value:        "bad host.example.com",
			target:       "example.com",
			wantAccepted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classifyMatchedIdentity(tt.value, tt.target)
			if ok != tt.wantAccepted {
				t.Fatalf("classifyMatchedIdentity(%q, %q) accepted = %v, want %v", tt.value, tt.target, ok, tt.wantAccepted)
			}
			if !tt.wantAccepted {
				return
			}
			if got.kind != tt.wantKind {
				t.Fatalf("kind = %q, want %q", got.kind, tt.wantKind)
			}
			if got.value != tt.wantValue {
				t.Fatalf("value = %q, want %q", got.value, tt.wantValue)
			}
		})
	}
}

func TestParseCertTimestamp(t *testing.T) {
	tests := []struct {
		input  string
		isZero bool
	}{
		{"2026-05-06T12:07:45", false},
		{"2026-05-06T12:07:45Z", false},
		{"2026-05-06T12:07:45+03:00", false},
		{"2026-05-06 12:07:45", false},
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

func TestClassifyIdentities(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	identities := []certificateIdentitySource{
		{value: "example.com", source: "crt.sh", NotAfter: future},
		{value: "example.com", source: "crt.sh", NotAfter: past},
		{value: "*.example.com", source: "crt.sh", NotAfter: future},
		{value: "a.example.com", source: "crt.sh", NotAfter: future},
		{value: "B.example.com", source: "Certspotter", NotAfter: past},
		{value: "a.example.com", source: "Certspotter", NotAfter: past},
		{value: "notexample.com", source: "crt.sh", NotAfter: future},
		{value: "sub.notexample.com", source: "crt.sh", NotAfter: future},
		{value: "deep.sub.example.com", source: "crt.sh", NotAfter: future},
		{value: "dove@alum.example.com", source: "crt.sh-pg", NotAfter: future},
		{value: "\"quoted\"@alum.example.com", source: "crt.sh-pg", NotAfter: future},
		{value: "user@gmail.com", source: "crt.sh-pg", NotAfter: future},
	}

	classified := classifyIdentities(identities, "example.com")

	if classified.targetMaxExpiry.Before(now) {
		t.Error("targetMaxExpiry should be in the future")
	}

	if len(classified.subdomains) != 4 {
		t.Errorf("expected 4 unique subdomains, got %d", len(classified.subdomains))
	}

	if got, ok := classified.subdomains["*.example.com"]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("*.example.com: expected future timestamp, got %+v", got)
	}

	if got, ok := classified.subdomains["a.example.com"]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("a.example.com: expected future timestamp, got %+v", got)
	}

	if got, ok := classified.subdomains["b.example.com"]; !ok || !got.notAfter.Equal(past) {
		t.Errorf("b.example.com: expected past timestamp, got %+v", got)
	}

	if _, ok := classified.subdomains["notexample.com"]; ok {
		t.Error("notexample.com should not be classified as a subdomain")
	}

	if len(classified.emails) != 1 {
		t.Errorf("expected 1 valid email, got %d", len(classified.emails))
	}

	if got, ok := classified.emails["dove@alum.example.com"]; !ok || !got.notAfter.Equal(future) {
		t.Errorf("dove@alum.example.com: expected future timestamp, got %+v", got)
	}
}

func TestFormatResults_CertExpiredFiltering(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains: map[string]classifiedIdentity{
			"active.example.com":  {notAfter: future, source: "crt.sh"},
			"expired.example.com": {notAfter: past, source: "crt.sh"},
			"unknown.example.com": {source: "crt.sh"},
		},
		emails: map[string]classifiedIdentity{
			"active@alum.example.com":  {notAfter: future, source: "crt.sh-pg"},
			"expired@alum.example.com": {notAfter: past, source: "crt.sh-pg"},
		},
		targetMaxExpiry: future,
		targetSource:    "crt.sh",
	}

	results := formatResults(classified, false)

	var subdomains, emails, certExpired, certNotAfter, emailNotAfter, statuses int
	for _, r := range results {
		switch r.Type {
		case resultTypeSubdomain, resultTypeWildcard:
			subdomains++
		case resultTypeEmail:
			emails++
		case "cert_expired_subdomains":
			certExpired++
		case resultTypeCertNotAfter:
			certNotAfter++
		case resultTypeEmailNotAfter:
			emailNotAfter++
		case resultTypeStatus:
			statuses++
		}
	}

	if subdomains != 2 {
		t.Errorf("with ghost filtering: expected 2 subdomain results, got %d", subdomains)
	}
	if emails != 2 {
		t.Errorf("with ghost filtering: expected 2 email results, got %d", emails)
	}
	if certExpired != 1 {
		t.Errorf("with ghost filtering: expected 1 cert_expired_subdomains result, got %d", certExpired)
	}
	if certNotAfter != 2 {
		t.Errorf("with ghost filtering: expected 2 cert_not_after results, got %d", certNotAfter)
	}
	if emailNotAfter != 2 {
		t.Errorf("with ghost filtering: expected 2 domain_cert_not_after results, got %d", emailNotAfter)
	}
	if statuses != 1 {
		t.Errorf("with ghost filtering: expected 1 status result, got %d", statuses)
	}
}

func TestFormatResults_DisableCertExpiredSubdomains(t *testing.T) {
	now := time.Now()
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains: map[string]classifiedIdentity{
			"active.example.com":  {notAfter: future, source: "crt.sh"},
			"expired.example.com": {notAfter: past, source: "crt.sh"},
		},
		emails: map[string]classifiedIdentity{
			"expired@alum.example.com": {notAfter: past, source: "crt.sh-pg"},
		},
		targetMaxExpiry: future,
		targetSource:    "crt.sh",
	}

	results := formatResults(classified, true)

	var subdomains, emails, certExpired, certNotAfter, emailNotAfter, statuses int
	for _, r := range results {
		switch r.Type {
		case resultTypeSubdomain, resultTypeWildcard:
			subdomains++
		case resultTypeEmail:
			emails++
		case "cert_expired_subdomains":
			certExpired++
		case resultTypeCertNotAfter:
			certNotAfter++
		case resultTypeEmailNotAfter:
			emailNotAfter++
		case resultTypeStatus:
			statuses++
		}
	}

	if subdomains != 2 {
		t.Errorf("with ghost disabled: expected 2 subdomain results, got %d", subdomains)
	}
	if emails != 1 {
		t.Errorf("with ghost disabled: expected 1 email result, got %d", emails)
	}
	if certExpired != 0 {
		t.Errorf("with ghost disabled: expected 0 cert_expired_subdomains results, got %d", certExpired)
	}
	if certNotAfter != 3 {
		t.Errorf("with ghost disabled: expected 3 cert_not_after results, got %d", certNotAfter)
	}
	if emailNotAfter != 1 {
		t.Errorf("with ghost disabled: expected 1 domain_cert_not_after result, got %d", emailNotAfter)
	}
	if statuses != 2 {
		t.Errorf("with ghost disabled: expected 2 status results, got %d", statuses)
	}
}

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(caps.Functions) != 1 || caps.Functions[0] != "get_domains" {
		t.Fatalf("expected 1 function get_domains, got %v", caps.Functions)
	}
}

func TestFormatResults_ExpiredTarget(t *testing.T) {
	past := time.Now().Add(-30 * 24 * time.Hour)

	classified := classifiedIdentities{
		subdomains:      make(map[string]classifiedIdentity),
		emails:          make(map[string]classifiedIdentity),
		targetMaxExpiry: past,
		targetSource:    "crt.sh",
	}

	results := formatResults(classified, false)

	if len(results) > 0 {
		t.Errorf("expected 0 results for expired target, got %d", len(results))
	}
}
