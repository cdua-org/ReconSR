package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestParseRPMailbox(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard mailbox", "admin.example.com.", "admin@example.com"},
		{"dotted local part", "first.last.example.com.", "first@last.example.com"},
		{"root mailbox", ".", ""},
		{"no trailing dot", "admin.example.com", "admin@example.com"},
		{"single label", "localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRPMailbox(tt.input)
			if got != tt.expected {
				t.Errorf("parseRPMailbox(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestProcessRPMailbox(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		target      string
		wantValue   string
		wantResults int
		wantOOS     bool
	}{
		{
			name:        "in-scope email stays node",
			input:       "hostmaster.example.com.",
			target:      "example.com",
			wantValue:   "hostmaster@example.com",
			wantResults: 1,
			wantOOS:     false,
		},
		{
			name:        "out-of-scope email becomes property",
			input:       "hostmaster.external.net.",
			target:      "example.com",
			wantValue:   "hostmaster@external.net",
			wantResults: 1,
			wantOOS:     true,
		},
		{
			name:        "invalid mailbox",
			input:       "invalid-mailbox",
			target:      "example.com",
			wantResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPMailbox(parseRPMailbox(tt.input), tt.target)
			if len(results) != tt.wantResults {
				t.Fatalf("processRPMailbox(%q, %q) returned %d results, want %d", tt.input, tt.target, len(results), tt.wantResults)
			}
			if tt.wantResults == 0 {
				return
			}

			result := results[0]
			if result.Type != "email" {
				t.Fatalf("unexpected type: got %q want %q", result.Type, "email")
			}
			if result.Category != categoryNode {
				t.Fatalf("unexpected category: got %q want %q", result.Category, categoryNode)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("unexpected value: got %q want %q", result.Value, tt.wantValue)
			}
			if result.Context != "RP Administrator Email" {
				t.Fatalf("unexpected context: got %q", result.Context)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("unexpected OutOfScope: got %v want %v", result.OutOfScope, tt.wantOOS)
			}
		})
	}
}

func TestProcessRPTXTDomain(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		target      string
		wantValue   string
		wantResults int
		wantOOS     bool
	}{
		{
			name:        "in-scope normalized domain",
			input:       "TXT.Example.COM.",
			target:      "example.com",
			wantResults: 1,
			wantValue:   "txt.example.com",
			wantOOS:     false,
		},
		{
			name:        "out-of-scope domain",
			input:       "txt.external.net.",
			target:      "example.com",
			wantResults: 1,
			wantValue:   "txt.external.net",
			wantOOS:     true,
		},
		{
			name:        "invalid domain",
			input:       "not a domain",
			target:      "example.com",
			wantResults: 0,
		},
		{
			name:        "root placeholder",
			input:       ".",
			target:      "example.com",
			wantResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPTXTDomain(tt.input, tt.target)
			if len(results) != tt.wantResults {
				t.Fatalf("processRPTXTDomain(%q, %q) returned %d results, want %d", tt.input, tt.target, len(results), tt.wantResults)
			}
			if tt.wantResults == 0 {
				return
			}

			result := results[0]
			if result.Type != "rp_domain" {
				t.Fatalf("unexpected type: got %q want %q", result.Type, "rp_domain")
			}
			if result.Category != categoryNode {
				t.Fatalf("unexpected category: got %q want %q", result.Category, categoryNode)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("unexpected value: got %q want %q", result.Value, tt.wantValue)
			}
			if result.Context != "RP TXT Reference Domain" {
				t.Fatalf("unexpected context: got %q", result.Context)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("unexpected OutOfScope: got %v want %v", result.OutOfScope, tt.wantOOS)
			}
		})
	}
}

type rpRecordExpectation struct {
	name            string
	record          string
	target          string
	wantEmail       string
	wantRPDomain    string
	wantCount       int
	wantEmailOOS    bool
	wantRPDomainOOS bool
}

func TestProcessRPRecord(t *testing.T) {
	tests := []rpRecordExpectation{
		{
			name:            "property email and rp domain",
			record:          "hostmaster.example.com. rp-info.example.com.",
			target:          "example.com",
			wantCount:       3,
			wantEmail:       "hostmaster@example.com",
			wantRPDomain:    "rp-info.example.com",
			wantEmailOOS:    false,
			wantRPDomainOOS: false,
		},
		{
			name:            "external rp domain",
			record:          "hostmaster.example.com. rp-info.external.net.",
			target:          "example.com",
			wantCount:       3,
			wantEmail:       "hostmaster@example.com",
			wantRPDomain:    "rp-info.external.net",
			wantEmailOOS:    false,
			wantRPDomainOOS: true,
		},
		{
			name:      "incomplete record keeps property only",
			record:    "hostmaster.example.com.",
			target:    "example.com",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPRecord(tt.record, tt.target)
			if len(results) != tt.wantCount {
				t.Fatalf("processRPRecord(%q, %q) returned %d results, want %d", tt.record, tt.target, len(results), tt.wantCount)
			}

			assertRPProperty(t, results, tt.record)
			if tt.wantCount == 1 {
				return
			}

			assertRPEmail(t, results, &tt)
			assertRPDomain(t, results, &tt)
		})
	}
}

func assertRPProperty(t *testing.T, results []schema.ModuleResult, record string) {
	t.Helper()

	property, ok := findResult(results, "rp", record)
	if !ok {
		t.Fatalf("missing rp property result for %q", record)
	}
	if property.Category != categoryProperty {
		t.Fatalf("unexpected property category: got %q want %q", property.Category, categoryProperty)
	}
}

func assertRPEmail(t *testing.T, results []schema.ModuleResult, expected *rpRecordExpectation) {
	t.Helper()

	email, ok := findResult(results, "email", expected.wantEmail)
	if !ok {
		t.Fatalf("missing email result %q", expected.wantEmail)
	}
	if email.Context != "RP Administrator Email" {
		t.Fatalf("unexpected email context: got %q", email.Context)
	}
	if email.Category != categoryNode {
		t.Fatalf("unexpected email category: got %q want %q", email.Category, categoryNode)
	}
	if email.OutOfScope != expected.wantEmailOOS {
		t.Fatalf("unexpected email OutOfScope: got %v want %v", email.OutOfScope, expected.wantEmailOOS)
	}
	assertRPSource(t, email.Source, expected.record, "email")
}

func assertRPDomain(t *testing.T, results []schema.ModuleResult, expected *rpRecordExpectation) {
	t.Helper()

	rpDomain, ok := findResult(results, "rp_domain", expected.wantRPDomain)
	if !ok {
		t.Fatalf("missing rp_domain result %q", expected.wantRPDomain)
	}
	if rpDomain.Context != "RP TXT Reference Domain" {
		t.Fatalf("unexpected rp_domain context: got %q", rpDomain.Context)
	}
	if rpDomain.Category != categoryNode {
		t.Fatalf("unexpected rp_domain category: got %q want %q", rpDomain.Category, categoryNode)
	}
	if rpDomain.OutOfScope != expected.wantRPDomainOOS {
		t.Fatalf("unexpected rp_domain OutOfScope: got %v want %v", rpDomain.OutOfScope, expected.wantRPDomainOOS)
	}
	assertRPSource(t, rpDomain.Source, expected.record, "rp_domain")
}

func assertRPSource(t *testing.T, source *schema.EntityRef, record, entityType string) {
	t.Helper()

	if source == nil {
		t.Fatalf("expected %s Source to reference RP property", entityType)
	}
	if source.Type != "rp" || source.Value != record {
		t.Fatalf("unexpected %s Source: got %+v want rp:%q", entityType, *source, record)
	}
}

func findResult(results []schema.ModuleResult, typ, value string) (schema.ModuleResult, bool) {
	idx := slices.IndexFunc(results, func(result schema.ModuleResult) bool {
		return result.Type == typ && result.Value == value
	})
	if idx == -1 {
		return schema.ModuleResult{}, false
	}
	return results[idx], true
}

func TestGetRPDataEmpty(t *testing.T) {
	execution := getRPData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("rp lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Found RP record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetRPDataNX(t *testing.T) {
	execution := getRPData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("rp lookup failed: %v", *execution.Error)
	}
}

func TestRPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, "get_rp") {
		t.Error("expected get_rp in capabilities")
	}
}
