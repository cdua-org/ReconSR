package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestParseRPMailbox(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard mailbox", "opsbox.example.com.", "opsbox@example.com"},
		{"dotted local part", "first.last.example.com.", "first@last.example.com"},
		{"root mailbox", ".", ""},
		{"no trailing dot", "opsbox.example.com", "opsbox@example.com"},
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
		wantValue   string
		wantResults int
		wantOOS     bool
	}{
		{
			name:        "in-scope email stays node",
			input:       "nocmail.example.com.",
			wantValue:   "nocmail@example.com",
			wantResults: 1,
			wantOOS:     false,
		},
		{
			name:        "out-of-scope email becomes property",
			input:       "nocmail.example.net.",
			wantValue:   "nocmail@example.net",
			wantResults: 1,
			wantOOS:     true,
		},
		{
			name:        "invalid mailbox",
			input:       "invalid-mailbox",
			wantResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPMailbox(parseRPMailbox(tt.input), "mailbox.rp.example.com", modutil.NewLocalIDGenerator())
			if len(results) != tt.wantResults {
				t.Fatalf("processRPMailbox(%q) returned %d results, want %d", tt.input, len(results), tt.wantResults)
			}
			if tt.wantResults == 0 {
				return
			}

			result := results[0]
			if result.Type != constants.TypeEmail {
				t.Fatalf("unexpected type: got %q want %q", result.Type, constants.TypeEmail)
			}
			if result.Category != constants.CategoryNode {
				t.Fatalf("unexpected category: got %q want %q", result.Category, constants.CategoryNode)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("unexpected value: got %q want %q", result.Value, tt.wantValue)
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
		wantValue   string
		wantResults int
		wantOOS     bool
	}{
		{
			name:        "in-scope normalized domain",
			input:       "TXT.EXAMPLE.COM.",
			wantResults: 1,
			wantValue:   "txt.example.com",
			wantOOS:     false,
		},
		{
			name:        "out-of-scope domain",
			input:       "txt.example.net.",
			wantResults: 1,
			wantValue:   "txt.example.net",
			wantOOS:     true,
		},
		{
			name:        "invalid domain",
			input:       "not a domain",
			wantResults: 0,
		},
		{
			name:        "root placeholder",
			input:       ".",
			wantResults: 0,
		},
		{
			name:        "self-referential domain",
			input:       "txt.rp.example.com.",
			wantResults: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPTXTDomain(tt.input, "txt.rp.example.com", modutil.NewLocalIDGenerator())
			if len(results) != tt.wantResults {
				t.Fatalf("processRPTXTDomain(%q) returned %d results, want %d", tt.input, len(results), tt.wantResults)
			}
			if tt.wantResults == 0 {
				return
			}

			result := results[0]
			if result.Type != constants.TypeSubdomain {
				t.Fatalf("unexpected type: got %q want %q", result.Type, constants.TypeSubdomain)
			}
			if !slices.Contains(result.Tags, constants.TagRP) {
				t.Fatalf("missing tag %q", constants.TagRP)
			}
			if result.Category != constants.CategoryNode {
				t.Fatalf("unexpected category: got %q want %q", result.Category, constants.CategoryNode)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("unexpected value: got %q want %q", result.Value, tt.wantValue)
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
			wantCount:       3,
			wantEmail:       "hostmaster@example.com",
			wantRPDomain:    "rp-info.example.com",
			wantEmailOOS:    false,
			wantRPDomainOOS: false,
		},
		{
			name:            "external rp domain",
			record:          "hostmaster.example.com. rp-info.example.net.",
			wantCount:       3,
			wantEmail:       "hostmaster@example.com",
			wantRPDomain:    "rp-info.example.net",
			wantEmailOOS:    false,
			wantRPDomainOOS: true,
		},
		{
			name:      "incomplete record keeps property only",
			record:    "hostmaster.example.com.",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := processRPRecord(tt.record, "record.rp.example.com", modutil.NewLocalIDGenerator())
			if len(results) != tt.wantCount {
				t.Fatalf("processRPRecord(%q) returned %d results, want %d", tt.record, len(results), tt.wantCount)
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

	property, ok := findResult(results, constants.TypeRP, record)
	if !ok {
		t.Fatalf("missing rp property result for %q", record)
	}
	if property.Category != constants.CategoryProperty {
		t.Fatalf("unexpected property category: got %q want %q", property.Category, constants.CategoryProperty)
	}
}

func assertRPEmail(t *testing.T, results []schema.ModuleResult, expected *rpRecordExpectation) {
	t.Helper()

	email, ok := findResult(results, constants.TypeEmail, expected.wantEmail)
	if !ok {
		t.Fatalf("missing email result %q", expected.wantEmail)
	}

	if email.Category != constants.CategoryNode {
		t.Fatalf("unexpected email category: got %q want %q", email.Category, constants.CategoryNode)
	}
	if email.OutOfScope != expected.wantEmailOOS {
		t.Fatalf("unexpected email OutOfScope: got %v want %v", email.OutOfScope, expected.wantEmailOOS)
	}
	assertRPSource(t, email.Source, expected.record, "email")
}

func assertRPDomain(t *testing.T, results []schema.ModuleResult, expected *rpRecordExpectation) {
	t.Helper()

	rpDomain, ok := findResult(results, constants.TypeSubdomain, expected.wantRPDomain)
	if !ok {
		t.Fatalf("missing RP domain result %q", expected.wantRPDomain)
	}
	if !slices.Contains(rpDomain.Tags, constants.TagRP) {
		t.Fatalf("missing tag %q", constants.TagRP)
	}

	if rpDomain.Category != constants.CategoryNode {
		t.Fatalf("unexpected RP domain category: got %q want %q", rpDomain.Category, constants.CategoryNode)
	}
	if rpDomain.OutOfScope != expected.wantRPDomainOOS {
		t.Fatalf("unexpected RP domain OutOfScope: got %v want %v", rpDomain.OutOfScope, expected.wantRPDomainOOS)
	}
	assertRPSource(t, rpDomain.Source, expected.record, "RP domain")
}

func assertRPSource(t *testing.T, source *schema.EntityRef, record, entityType string) {
	t.Helper()

	if source == nil {
		t.Fatalf("expected %s Source to reference RP property", entityType)
	}
	if source.Type != constants.TypeRP || source.Value != record {
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
	execution := getRPData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("rp lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) > 0 {
		t.Logf("Found RP record for example.com: %v", execution.Results[0].Value)
	}
}

func TestGetRPDataNX(t *testing.T) {
	execution := getRPData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

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

	if !slices.Contains(caps.Functions, constants.FuncGetRP) {
		t.Error("expected get_rp in capabilities")
	}
}
