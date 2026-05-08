package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func resultTypes(results []schema.ModuleResult) []string {
	types := make([]string, 0, len(results))
	for _, result := range results {
		types = append(types, result.Type)
	}
	return types
}

func resultValues(results []schema.ModuleResult) []string {
	values := make([]string, 0, len(results))
	for _, result := range results {
		values = append(values, result.Value)
	}
	return values
}

func TestParseCAARecord(t *testing.T) {
	const (
		authorityDomain = "ca.example.com"
		issueRecord     = `0 issue "ca.example.com"`
	)

	tests := []struct {
		name           string
		record         string
		expectedTypes  []string
		expectedValues []string
	}{
		{
			name:           "issue basic",
			record:         issueRecord,
			expectedTypes:  []string{constants.TypeCAA, constants.TypeCertAuthority},
			expectedValues: []string{issueRecord, authorityDomain},
		},
		{
			name:           "issue normalizes authority domain",
			record:         `0 issue "CA.EXAMPLE.COM"`,
			expectedTypes:  []string{constants.TypeCAA, constants.TypeCertAuthority},
			expectedValues: []string{`0 issue "CA.EXAMPLE.COM"`, "ca.example.com"},
		},
		{
			name:           "iodef email",
			record:         `0 iodef "mailto:Security@Example.COM"`,
			expectedTypes:  []string{constants.TypeCAA, constants.TypeEmail},
			expectedValues: []string{`0 iodef "mailto:Security@Example.COM"`, "Security@example.com"},
		},
		{
			name:           "issue with parameters",
			record:         `0 issue "ca.example.net; cansignhttpexchanges=yes"`,
			expectedTypes:  []string{constants.TypeCAA, constants.TypeCertAuthority},
			expectedValues: []string{`0 issue "ca.example.net; cansignhttpexchanges=yes"`, "ca.example.net"},
		},
		{
			name:           "hex encoded issue",
			record:         `\# 21 00 05 69 73 73 75 65 63 61 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d`,
			expectedTypes:  []string{constants.TypeCAA, constants.TypeCertAuthority},
			expectedValues: []string{issueRecord, authorityDomain},
		},
		{
			name:           "invalid authority skipped",
			record:         `0 issue "bad domain"`,
			expectedTypes:  []string{constants.TypeCAA},
			expectedValues: []string{`0 issue "bad domain"`},
		},
		{
			name:           "invalid iodef email skipped",
			record:         `0 iodef "mailto:not-an-email"`,
			expectedTypes:  []string{constants.TypeCAA},
			expectedValues: []string{`0 iodef "mailto:not-an-email"`},
		},
		{
			name:           "iodef http value not emitted without validator support",
			record:         `0 iodef "https://example.com/abuse"`,
			expectedTypes:  []string{constants.TypeCAA},
			expectedValues: []string{`0 iodef "https://example.com/abuse"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := parseCAARecord(tt.record)
			if got := resultTypes(results); !slices.Equal(got, tt.expectedTypes) {
				t.Fatalf("unexpected result types: got %v want %v", got, tt.expectedTypes)
			}
			if got := resultValues(results); !slices.Equal(got, tt.expectedValues) {
				t.Fatalf("unexpected result values: got %v want %v", got, tt.expectedValues)
			}
		})
	}
}

func TestGetCAAData(t *testing.T) {
	res := getCAAData(context.Background(), "example.com")

	switch {
	case res.Error != nil:
		t.Logf("Network resolution error: %v", *res.Error)
	case len(res.Results) == 0:
		t.Log("No CAA records found for example.com")
	default:
		if res.Results[0].Type != constants.TypeCAA {
			t.Errorf("expected type 'caa' (raw CAA), got '%s'", res.Results[0].Type)
		}
	}
}

func TestCAACapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetCAA) {
		t.Error("expected get_caa in capabilities")
	}
}
