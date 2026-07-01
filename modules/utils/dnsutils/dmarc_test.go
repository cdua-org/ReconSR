package dnsutils

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func formatDMARCRecord(parsed map[string]string) string {
	parts := make([]string, 0, len(parsed))
	seen := make(map[string]struct{}, len(parsed))

	for _, key := range []string{"v", "p", "sp", "aspf", "rua", "ruf"} {
		value, ok := parsed[key]
		if !ok {
			continue
		}

		parts = append(parts, key+"="+value)
		seen[key] = struct{}{}
	}

	if len(seen) == len(parsed) {
		return strings.Join(parts, "; ")
	}

	extraParts := make([]string, 0, len(parsed)-len(seen))
	for key, value := range parsed {
		if _, ok := seen[key]; ok {
			continue
		}
		extraParts = append(extraParts, key+"="+value)
	}

	slices.Sort(extraParts)
	parts = append(parts, extraParts...)

	return strings.Join(parts, "; ")
}

func TestParseDMARC(t *testing.T) {
	const (
		quarantineRecord = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
		noneRecord       = "v=DMARC1; p=none"
	)

	tests := []struct {
		expected string
		name     string
		input    string
	}{
		{
			expected: quarantineRecord,
			name:     "full policy",
			input:    quarantineRecord,
		},
		{
			expected: noneRecord,
			name:     "minimal record",
			input:    noneRecord,
		},
		{
			expected: "v=DMARC1; p=reject; sp=quarantine; aspf=r",
			name:     "with sp and aspf",
			input:    "v=DMARC1; p=reject; sp=quarantine; aspf=r",
		},
		{
			expected: "v=DMARC1; p=",
			name:     "empty value",
			input:    "v=DMARC1; p=",
		},
		{
			expected: noneRecord,
			name:     "empty parts and malformed",
			input:    "v=DMARC1; ; =bad; broken; p=none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDMARCRecord(ParseDMARC(tt.input))
			if got != tt.expected {
				t.Errorf("ParseDMARC() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractDMARCEmails(t *testing.T) {
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
			input:    "mailto:email1@example.com,mailto:email2@example.net",
			expected: []string{"email1@example.com", "email2@example.net"},
		},
		{
			name:     "multiple emails first with mailto",
			input:    "mailto:email1@example.com,email2@example.net",
			expected: []string{"email1@example.com", "email2@example.net"},
		},
		{
			name:     "real world multiple emails",
			input:    "mailto:uuid@dmarc-reports.example.com,mailto:alert@example.net",
			expected: []string{"uuid@dmarc-reports.example.com", "alert@example.net"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDMARCEmails(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ExtractDMARCEmails() = %v, want %v", got, tt.expected)
			}
		})
	}
}
