package dns

import (
	"context"
	"reflect"
	"slices"
	"testing"
)

func TestGetDMARCDataEmpty(t *testing.T) {
	execution := getDMARCData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("dmarc lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetDMARCData(t *testing.T) {
	res := getDMARCData(context.Background(), "example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else if len(res.Results) == 0 {
		t.Log("No DMARC records found for example.com")
	}
}

func TestDMARCCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_dmarc") {
		t.Error("expected get_dmarc in capabilities")
	}
}

func TestFilterDMARC(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid DMARC record",
			input:    []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
			expected: []string{"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
		},
		{
			name:     "multiple records with DMARC",
			input:    []string{"v=DKIM1", "v=DMARC1; p=none", "v=SPF1"},
			expected: []string{"v=DMARC1; p=none"},
		},
		{
			name:     "no DMARC records",
			input:    []string{"v=DKIM1", "v=SPF1"},
			expected: nil,
		},
		{
			name:     "empty input",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "case insensitive - different case not matched",
			input:    []string{"V=DMARC1; p=reject"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("filterDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		expected map[string]string
		name     string
		input    string
	}{
		{
			expected: map[string]string{"v": "DMARC1", "p": "quarantine", "rua": "mailto:dmarc@example.com"},
			name:     "full policy",
			input:    "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": "none"},
			name:     "minimal record",
			input:    "v=DMARC1; p=none",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": "reject", "sp": "quarantine", "aspf": "r"},
			name:     "with sp and aspf",
			input:    "v=DMARC1; p=reject; sp=quarantine; aspf=r",
		},
		{
			expected: map[string]string{"v": "DMARC1", "p": ""},
			name:     "empty value",
			input:    "v=DMARC1; p=;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDMARC(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseDMARC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExtractEmails(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single email with mailto",
			input:    "mailto:dmarc@example.com",
			expected: []string{"dmarc@example.com"},
		},
		{
			name:     "multiple emails comma separated",
			input:    "mailto:email1@example.com,mailto:email2@example.com",
			expected: []string{"email1@example.com", "email2@example.com"},
		},
		{
			name:     "multiple emails first with mailto",
			input:    "mailto:email1@example.com,email2@example.com",
			expected: []string{"email1@example.com", "email2@example.com"},
		},
		{
			name:     "real world multiple emails",
			input:    "mailto:uuid@dmarc-reports.example.com,mailto:alert@example.tld",
			expected: []string{"uuid@dmarc-reports.example.com", "alert@example.tld"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEmails(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("extractEmails() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestProcessDMARCEmailsSkipsInvalidAndNormalizes(t *testing.T) {
	results := processDMARCEmails("example.com", map[string]string{
		"rua": "mailto:Admin@EXAMPLE.COM,mailto:bad@@example.com",
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != "email" {
		t.Fatalf("expected type email, got %q", results[0].Type)
	}

	if results[0].Value != "Admin@example.com" {
		t.Fatalf("expected normalized email, got %q", results[0].Value)
	}

	if results[0].Context != "DMARC RUA #1" {
		t.Fatalf("expected indexed context, got %q", results[0].Context)
	}

	if results[0].OutOfScope {
		t.Fatal("expected in-scope email")
	}
}

func TestProcessDMARCEmailsUsesValidatedType(t *testing.T) {
	results := processDMARCEmails("example.com", map[string]string{
		"ruf": "mailto:\"john\"@example.com",
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != "email-extra" {
		t.Fatalf("expected type email-extra, got %q", results[0].Type)
	}

	if results[0].Value != "\"john\"@example.com" {
		t.Fatalf("expected validated email-extra value, got %q", results[0].Value)
	}

	if results[0].Context != "DMARC RUF" {
		t.Fatalf("expected non-indexed context, got %q", results[0].Context)
	}
}
