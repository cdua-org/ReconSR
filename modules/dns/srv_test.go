package dns

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
)

func TestParseSRVHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid SRV record",
			input:    "10 50 5060 sipserver.example.com.",
			expected: "sipserver.example.com",
			wantErr:  false,
		},
		{
			name:     "invalid - too few fields",
			input:    "10 50 5060",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "invalid - non-numeric port",
			input:    "10 50 sip sipserver.example.com.",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSRVHost(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSRVHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseSRVHost() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestBuildSRVHostResult(t *testing.T) {
	const targetDomain = "example.com"
	tests := []struct {
		name      string
		host      string
		target    string
		wantValue string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "valid host gets normalized",
			host:      "sip.example.com.",
			target:    targetDomain,
			wantValue: "sip.example.com",
			wantOK:    true,
			wantOOS:   false,
		},
		{
			name:      "out of scope host",
			host:      "sip.otherdomain.com",
			target:    targetDomain,
			wantValue: "sip.otherdomain.com",
			wantOK:    true,
			wantOOS:   true,
		},
		{
			name:      "invalid host is skipped",
			host:      "invalid_host",
			target:    targetDomain,
			wantValue: "",
			wantOK:    false,
			wantOOS:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := buildSRVHostResult(tt.host, tt.target)
			if ok != tt.wantOK {
				t.Fatalf("buildSRVHostResult() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if result.Type != constants.TypeDomain {
				t.Fatalf("buildSRVHostResult() type = %q, want %q", result.Type, constants.TypeDomain)
			}
			if !slices.Contains(result.Tags, constants.TagSRV) {
				t.Fatalf("buildSRVHostResult() missing tag %q", constants.TagSRV)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("buildSRVHostResult() value = %q, want %q", result.Value, tt.wantValue)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("buildSRVHostResult() out_of_scope = %v, want %v", result.OutOfScope, tt.wantOOS)
			}
		})
	}
}

func TestGetSRVDataEmpty(t *testing.T) {
	execution := getSRVData(context.Background(), "nonexistent.domain.invalid")

	if execution.Error != nil {
		t.Logf("srv lookup failed: %v", *execution.Error)
		return
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d: %+v", len(execution.Results), execution.Results)
	}
}

func TestSRVCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSRV) {
		t.Error("expected get_srv in capabilities")
	}
}
