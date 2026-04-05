package dns

import (
	"reflect"
	"slices"
	"testing"
)

func TestGetDMARCDataEmpty(t *testing.T) {
	execution := getDMARCData("nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("dmarc lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(execution.Results))
	}

	result := execution.Results[0]
	if result.Type != "string" || result.Value != "No DMARC" {
		t.Errorf("expected 'No DMARC' result, got %+v", result)
	}
	if result.Context != "DMARC Records" {
		t.Errorf("expected context 'DMARC Records', got %q", result.Context)
	}
}

func TestGetDMARCData(t *testing.T) {
	res := getDMARCData("example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else if len(res.Results) == 0 {
		t.Error("expected at least one DMARC result or 'No DMARC'")
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
