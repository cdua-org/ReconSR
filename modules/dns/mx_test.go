package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestParseMX(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected mxRecord
		wantErr  bool
	}{
		{
			name:     "valid MX record",
			input:    "10 mail.example.com.",
			expected: mxRecord{host: "mail.example.com", pref: 10},
			wantErr:  false,
		},
		{
			name:     "MX with high priority",
			input:    "1 mx.example.net.",
			expected: mxRecord{host: "mx.example.net", pref: 1},
			wantErr:  false,
		},
		{
			name:     "invalid - too few fields",
			input:    "mail.example.com.",
			expected: mxRecord{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMX(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && (got.host != tt.expected.host || got.pref != tt.expected.pref) {
				t.Errorf("parseMX() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestBuildMXHostResult(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		target    string
		wantValue string
		wantType  string
		wantNil   bool
		wantOOS   bool
	}{
		{
			name:      "in scope subdomain host",
			host:      "MAIL.MX-SCOPE.EXAMPLE.COM",
			target:    "mx-scope.example.com",
			wantType:  constants.TypeSubdomain,
			wantValue: "mail.mx-scope.example.com",
		},
		{
			name:    "invalid host is skipped",
			host:    "bad host",
			target:  "mx-invalid.example.com",
			wantNil: true,
		},
		{
			name:    "self referential host is skipped",
			host:    "mx-self.example.com",
			target:  "mx-self.example.com",
			wantNil: true,
		},
		{
			name:      "out of scope host",
			host:      "relay.mx-external.example.org",
			target:    "mx-oos.example.com",
			wantType:  constants.TypeSubdomain,
			wantValue: "relay.mx-external.example.org",
			wantOOS:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &schema.EntityRef{Type: constants.TypeMX, Value: "10 " + tt.host}
			result := buildMXHostResult(source, tt.host, tt.target)
			if tt.wantNil {
				if result != nil {
					t.Fatalf("expected nil result, got %+v", result)
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Type != tt.wantType {
				t.Fatalf("type = %q, want %q", result.Type, tt.wantType)
			}
			if !slices.Contains(result.Tags, constants.TagMX) {
				t.Fatalf("missing tag %q", constants.TagMX)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("value = %q, want %q", result.Value, tt.wantValue)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("out_of_scope = %v, want %v", result.OutOfScope, tt.wantOOS)
			}
			if result.Source == nil || result.Source.Type != source.Type || result.Source.Value != source.Value {
				t.Fatalf("expected source %+v, got %+v", source, result.Source)
			}
		})
	}
}

func TestGetMXDataEmpty(t *testing.T) {
	execution := getMXData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("mx lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetMXData(t *testing.T) {
	res := getMXData(context.Background(), "mx-lookup.example.com")

	if res.Error != nil {
		t.Logf("Network resolution error: %v", *res.Error)
	} else if len(res.Results) == 0 {
		t.Log("No MX records found for example.com, which is possible but rare in this specific test")
	}
}

func TestMXCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetMX) {
		t.Error("expected get_mx in capabilities")
	}
}
