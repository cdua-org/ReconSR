package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestParseNAPTRRecord(t *testing.T) {
	const standardRecord = "100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" _sip._udp.example.com."

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard naptr",
			standardRecord,
			standardRecord,
		},
		{
			"wire format passthrough",
			"\\# 20 0064000a0173075349502b4432550000",
			"\\# 20 0064000a0173075349502b4432550000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNAPTRRecord(tt.input)
			if got != tt.expected {
				t.Errorf("parseNAPTRRecord() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractNAPTRServiceAndReplacement(t *testing.T) {
	tests := []struct {
		name                string
		parsed              string
		wantService         string
		wantReplacement     string
		wantParsedSucceeded bool
	}{
		{
			name:                "quoted regexp field",
			parsed:              "100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" sip1.example.com.",
			wantService:         "SIP+D2U",
			wantReplacement:     "sip1.example.com.",
			wantParsedSucceeded: true,
		},
		{
			name:                "empty regexp collapsed by resolver",
			parsed:              "10 100 s SIP+D2T  _sip._tcp.voice.example.org.",
			wantService:         "SIP+D2T",
			wantReplacement:     "_sip._tcp.voice.example.org.",
			wantParsedSucceeded: true,
		},
		{
			name:                "too short",
			parsed:              "10 100 s SIP+D2T",
			wantParsedSucceeded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotService, gotReplacement, ok := extractNAPTRServiceAndReplacement(tt.parsed)
			if ok != tt.wantParsedSucceeded {
				t.Fatalf("extractNAPTRServiceAndReplacement() ok = %v, want %v", ok, tt.wantParsedSucceeded)
			}
			if !ok {
				return
			}
			if gotService != tt.wantService {
				t.Fatalf("unexpected service: %q", gotService)
			}
			if gotReplacement != tt.wantReplacement {
				t.Fatalf("unexpected replacement: %q", gotReplacement)
			}
		})
	}
}

func TestBuildNAPTRServiceResult(t *testing.T) {
	const parsedRecord = "100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" _sip._udp.example.com."

	result := buildNAPTRServiceResult(parsedRecord, "SIP+D2U")
	if result.Type != constants.TypeNAPTR {
		t.Fatalf("unexpected type: %s", result.Type)
	}
	if result.Category != constants.CategoryProperty {
		t.Fatalf("unexpected category: %s", result.Category)
	}
	if result.Value != "SIP+D2U" {
		t.Fatalf("unexpected value: %s", result.Value)
	}
	if result.Context != "NAPTR Service" {
		t.Fatalf("unexpected context: %s", result.Context)
	}
	if result.Source == nil {
		t.Fatal("expected source reference")
	}
	if result.Source.Type != constants.TypeNAPTR || result.Source.Value != parsedRecord {
		t.Fatalf("unexpected source: %#v", result.Source)
	}
}

func TestBuildNAPTRTargetResult(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		replacement string
		wantValue   string
		wantType    string
		wantOOS     bool
	}{
		{
			name:        "normalizes regular domain replacement",
			target:      "target.naptr.example.com",
			replacement: "SIP.EXAMPLE.COM.",
			wantValue:   "sip.example.com",
			wantType:    constants.TypeSubdomain,
			wantOOS:     false,
		},
		{
			name:        "returns full service owner replacement after base-domain validation",
			target:      "example.net",
			replacement: "_sip._tcp.example.net.",
			wantValue:   "_sip._tcp.example.net",
			wantType:    constants.TypeSubdomain,
			wantOOS:     false,
		},
		{
			name:        "marks validated service owner replacement out of scope",
			target:      "target.naptr.example.com",
			replacement: "_sips._tcp.voice.example.org.",
			wantValue:   "_sips._tcp.voice.example.org",
			wantType:    constants.TypeSubdomain,
			wantOOS:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &schema.EntityRef{Type: constants.TypeNAPTR, Value: "naptr-service"}
			result := buildNAPTRTargetResult(source, tt.target, tt.replacement)
			if result == nil {
				t.Fatal("expected naptr target result")
			}
			if result.Type != tt.wantType {
				t.Fatalf("unexpected type: %s", result.Type)
			}
			if !slices.Contains(result.Tags, constants.TagNAPTR) {
				t.Fatalf("missing tag %q", constants.TagNAPTR)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("unexpected value: %s", result.Value)
			}
			if result.Context != "Replacement Target" {
				t.Fatalf("unexpected context: %s", result.Context)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("unexpected out_of_scope: %v", result.OutOfScope)
			}
			if result.Source == nil {
				t.Fatal("expected source reference")
			}
			if result.Source.Type != source.Type || result.Source.Value != source.Value {
				t.Fatalf("unexpected source: %#v", result.Source)
			}
		})
	}
}

func TestBuildNAPTRTargetResultInvalid(t *testing.T) {
	tests := []string{".", "", "bad target", "\"quoted\"", "_sip.only-one-prefix.example.org.", "_sip._tcp.invalid_target"}
	source := &schema.EntityRef{Type: constants.TypeNAPTR, Value: "naptr-service"}
	for _, replacement := range tests {
		if result := buildNAPTRTargetResult(source, "invalid.naptr.example.com", replacement); result != nil {
			t.Fatalf("expected nil result for replacement %q", replacement)
		}
	}
}

func TestGetNAPTRDataEmpty(t *testing.T) {
	execution := getNAPTRData(context.Background(), "example.com")

	if execution.Error != nil {
		t.Logf("naptr lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d NAPTR results for example.com", len(execution.Results))
}

func TestGetNAPTRDataNX(t *testing.T) {
	execution := getNAPTRData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("naptr lookup failed: %v", *execution.Error)
	}
}

func TestNAPTRCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetNAPTR) {
		t.Error("expected get_naptr in capabilities")
	}
}
