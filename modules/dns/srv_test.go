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
			input:    "10 0 5222 xmpp.example.com.",
			expected: "xmpp.example.com",
			wantErr:  false,
		},
		{
			name:     "invalid - too few fields",
			input:    "10 0 xmpp.example.com.",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "invalid - non-numeric port",
			input:    "10 0 port xmpp.example.com.",
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
			if !tt.wantErr && !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseSRVHost() = %+v, want %+v", got, tt.expected)
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
