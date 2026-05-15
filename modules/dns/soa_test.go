package dns

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestParseSOA(t *testing.T) {
	tests := []struct {
		expected *SOA
		name     string
		input    string
	}{
		{
			name:  "valid SOA",
			input: "ns1.example.com. hostmaster.example.com. 2024031501 7200 3600 1209600 86400",
			expected: &SOA{
				NS:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  2024031501,
				Refresh: 7200,
				Retry:   3600,
				Expire:  1209600,
				MinTTL:  86400,
			},
		},
		{
			name:  "minimal SOA",
			input: "ns.example.com. admin.example.com. 1 100 200 300 400",
			expected: &SOA{
				NS:      "ns.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  1,
				Refresh: 100,
				Retry:   200,
				Expire:  300,
				MinTTL:  400,
			},
		},
		{
			name:     "invalid too few fields",
			input:    "ns.example.com. admin.example.com.",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSOA(tt.input)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseSOA() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestFormatMbox(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"opsmail.example.com.", "opsmail@example.com"},
		{"adminbox.example.com.", "adminbox@example.com"},
		{"dnsbox.example.net.", "dnsbox@example.net"},
		{"no.dot.email", "no@dot.email"},
		{"single.word", "single@word"},
		{"nodotsatall", "nodotsatall"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := formatMbox(tt.input)
			if got != tt.expected {
				t.Errorf("formatMbox(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseUint(t *testing.T) {
	tests := []struct {
		input    string
		expected uint32
	}{
		{"12345", 12345},
		{"0", 0},
		{"4294967295", 4294967295},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseUint(tt.input)
			if got != tt.expected {
				t.Errorf("parseUint(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildSOAPrimaryNSResultSkipsInvalidAndNormalizes(t *testing.T) {
	result := buildSOAPrimaryNSResult("NS1.EXAMPLE.COM.", "primary.soa.example.com")
	if result == nil {
		t.Fatal("expected primary NS result")
	}

	if result.Type != constants.TypeSubdomain {
		t.Fatalf("expected type subdomain, got %q", result.Type)
	}

	if result.Value != "ns1.example.com" {
		t.Fatalf("expected normalized NS value, got %q", result.Value)
	}

	if !slices.Contains(result.Tags, constants.TagNS) {
		t.Fatalf("expected ns tag, got %v", result.Tags)
	}

	if result.Context != "Primary NS" {
		t.Fatalf("expected primary NS context, got %q", result.Context)
	}

	if result.OutOfScope {
		t.Fatal("expected in-scope NS")
	}

	if buildSOAPrimaryNSResult(".bad.example.com.", "primary.soa.example.com") != nil {
		t.Fatal("expected invalid primary NS to be skipped")
	}
}

func TestBuildSOAResponsibleEmailResultSkipsInvalidAndUsesValidatedType(t *testing.T) {
	result := buildSOAResponsibleEmailResult(`"john".example.com.`, "responsible.soa.example.com")
	if result == nil {
		t.Fatal("expected responsible email result")
	}

	if result.Type != constants.TypeEmailExtra {
		t.Fatalf("expected type email-extra, got %q", result.Type)
	}

	if result.Value != `"john"@example.com` {
		t.Fatalf("expected validated responsible email value, got %q", result.Value)
	}

	if result.Context != "Responsible Email" {
		t.Fatalf("expected responsible email context, got %q", result.Context)
	}

	if result.OutOfScope {
		t.Fatal("expected in-scope responsible email")
	}

	if buildSOAResponsibleEmailResult("bad..example.com.", "responsible.soa.example.com") != nil {
		t.Fatal("expected invalid responsible email to be skipped")
	}
}

func TestGetSOAData(t *testing.T) {
	res := getSOAData(context.Background(), "example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Log("No SOA records found for example.com")
	default:
		if len(res.Results) != 4 {
			t.Errorf("expected 4 results, got %d", len(res.Results))
		}
	}
}

func TestSOACapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSOA) {
		t.Error("expected get_soa in capabilities")
	}
}
