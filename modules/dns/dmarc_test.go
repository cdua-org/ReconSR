package dns

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
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

	if !slices.Contains(caps.Functions, constants.FuncGetDMARC) {
		t.Error("expected get_dmarc in capabilities")
	}
}

func TestFilterDMARC(t *testing.T) {
	const (
		quarantineRecord = "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
		noneRecord       = "v=DMARC1; p=none"
	)

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "valid DMARC record",
			input:    []string{quarantineRecord},
			expected: []string{quarantineRecord},
		},
		{
			name:     "multiple records with DMARC",
			input:    []string{"v=DKIM1", noneRecord, "v=SPF1"},
			expected: []string{noneRecord},
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

func TestProcessDMARCEmailsSkipsInvalidAndNormalizes(t *testing.T) {
	source := &schema.EntityRef{Type: constants.TypeDMARC, Value: "v=DMARC1"}
	parsed := map[string]string{"rua": "mailto:Admin@EXAMPLE.COM,mailto:bad@@example.com"}
	results := processDMARCEmails("rua.dmarc.example.com", parsed, source)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != constants.TypeEmail {
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

	if results[0].Source != source {
		t.Fatal("expected source to be attached")
	}
}

func TestProcessDMARCEmailsUsesValidatedType(t *testing.T) {
	source := &schema.EntityRef{Type: constants.TypeDMARC, Value: "v=DMARC1"}
	parsed := map[string]string{"ruf": `mailto:"john"@example.com`}
	results := processDMARCEmails("ruf.dmarc.example.com", parsed, source)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Type != constants.TypeEmailExtra {
		t.Fatalf("expected type email-extra, got %q", results[0].Type)
	}

	if results[0].Value != `"john"@example.com` {
		t.Fatalf("expected validated email-extra value, got %q", results[0].Value)
	}

	if results[0].Context != "DMARC RUF" {
		t.Fatalf("expected non-indexed context, got %q", results[0].Context)
	}
	if results[0].Source != source {
		t.Fatal("expected source to be attached")
	}
}
