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

func TestBuildNAPTRServiceResult(t *testing.T) {
	const parsedRecord = "100 10 \"s\" \"SIP+D2U\" \"!^.*$!sip:customer@example.com!\" _sip._udp.example.com."

	result := buildNAPTRServiceResult(parsedRecord, "SIP+D2U", modutil.NewLocalIDGenerator())
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
		wantContext string
		wantNil     bool
		wantOOS     bool
	}{
		{
			name:        "normalizes regular domain replacement",
			target:      "target.naptr.example.com",
			replacement: "SIP.EXAMPLE.COM.",
			wantNil:     false,
			wantValue:   "sip.example.com",
			wantType:    constants.TypeSubdomain,
			wantOOS:     false,
			wantContext: "NAPTR Target (SIP.EXAMPLE.COM.)",
		},
		{
			name:        "skips self referential replacement after base-domain validation",
			target:      "example.net",
			replacement: "_sip._tcp.example.net.",
			wantNil:     true,
		},
		{
			name:        "marks validated service owner replacement out of scope",
			target:      "target.naptr.example.com",
			replacement: "_sips._tcp.voice.example.org.",
			wantNil:     false,
			wantValue:   "voice.example.org",
			wantType:    constants.TypeSubdomain,
			wantOOS:     true,
			wantContext: "NAPTR Target (_sips._tcp.voice.example.org.)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &schema.EntityRef{Type: constants.TypeNAPTR, Value: "naptr-service"}
			result := buildNAPTRTargetResult(source, tt.target, tt.replacement, modutil.NewLocalIDGenerator())
			if tt.wantNil {
				if result != nil {
					t.Fatalf("expected nil result, got %+v", result)
				}
				return
			}
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
			if result.Context != tt.wantContext {
				t.Fatalf("unexpected context: %s, want %s", result.Context, tt.wantContext)
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
		if result := buildNAPTRTargetResult(source, "invalid.naptr.example.com", replacement, modutil.NewLocalIDGenerator()); result != nil {
			t.Fatalf("expected nil result for replacement %q", replacement)
		}
	}
}

func TestBuildNAPTRRegexpResults(t *testing.T) {
	source := &schema.EntityRef{Type: constants.TypeNAPTR, Value: "E2U+sip"}

	results := buildNAPTRRegexpResults(source, "!^.*$!sip:info@example.org!", "sip:info@example.org", modutil.NewLocalIDGenerator())
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	regexpProp := results[0]
	if regexpProp.Type != constants.TypeNAPTR || regexpProp.Value != "!^.*$!sip:info@example.org!" || regexpProp.Context != "NAPTR Regexp" {
		t.Fatalf("unexpected regexp property: %#v", regexpProp)
	}
	if regexpProp.Source == nil || regexpProp.Source.Type != source.Type || regexpProp.Source.Value != source.Value {
		t.Fatalf("unexpected regexp source: %#v", regexpProp.Source)
	}

	targetProp := results[1]
	if targetProp.Type != constants.TypeURL || targetProp.Value != "sip:info@example.org" || targetProp.Context != "NAPTR Regexp Target" {
		t.Fatalf("unexpected target property: %#v", targetProp)
	}
	if targetProp.Source == nil || targetProp.Source.Type != constants.TypeNAPTR || targetProp.Source.Value != "!^.*$!sip:info@example.org!" {
		t.Fatalf("unexpected target source: %#v", targetProp.Source)
	}

	// Test without target
	resultsOnlyRegexp := buildNAPTRRegexpResults(source, "!^.*$!$1!", "", modutil.NewLocalIDGenerator())
	if len(resultsOnlyRegexp) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resultsOnlyRegexp))
	}
}

func TestGetNAPTRDataEmpty(t *testing.T) {
	execution := getNAPTRData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("naptr lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d NAPTR results for example.com", len(execution.Results))
}

func TestGetNAPTRDataNX(t *testing.T) {
	execution := getNAPTRData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

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
