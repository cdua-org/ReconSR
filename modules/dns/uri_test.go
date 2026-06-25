package dns

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetURIData(t *testing.T) {
	tests := []struct {
		mockError     error
		name          string
		target        string
		mockRecords   []string
		expectedCount int
		expectError   bool
	}{
		{
			mockError:     nil,
			name:          "uri lookup success",
			target:        "geturi.example.com",
			mockRecords:   []string{"10 100 \"https://example.com\""},
			expectedCount: 2,
			expectError:   false,
		},
		{
			mockError:     nil,
			name:          "uri lookup unparsed",
			target:        "unparsed.geturi.example.net",
			mockRecords:   []string{"invalid_uri_record"},
			expectedCount: 0,
			expectError:   false,
		},
		{
			mockError:     nil,
			name:          "uri lookup empty",
			target:        "empty.geturi.example.org",
			mockRecords:   []string{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "uri lookup err",
			target:        "error.geturi.example.com",
			mockRecords:   nil,
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origResolveRecordFunc := resolveRecordFunc
			defer func() { resolveRecordFunc = origResolveRecordFunc }()

			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				if tt.mockError != nil {
					return nil, nil, tt.mockError
				}
				return tt.mockRecords, []byte("mock raw data"), nil
			}

			execution := getURIData(context.Background(), tt.target, modutil.NewLocalIDGenerator())

			if tt.expectError {
				if execution.Error == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if execution.Error != nil {
					t.Errorf("unexpected error: %v", *execution.Error)
				}
				if len(execution.Results) != tt.expectedCount {
					t.Errorf("expected %d results, got %d", tt.expectedCount, len(execution.Results))
				}
			}
		})
	}
}

func TestURICapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetURI) {
		t.Error("expected get_uri in capabilities")
	}
}

func TestBuildURIResults(t *testing.T) {
	parsed := &dnsutils.URIRecord{
		Priority:  "10",
		Weight:    "100",
		Target:    "https://example.com",
		Formatted: "10 100 \"https://example.com\"",
	}
	source := &schema.EntityRef{Type: constants.TypeURI, Value: parsed.Formatted}

	results := buildURIResults(parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if res.Type != constants.TypeURL {
		t.Errorf("expected type %s, got %s", constants.TypeURL, res.Type)
	}
	if res.Value != parsed.Target {
		t.Errorf("expected value %s, got %s", parsed.Target, res.Value)
	}
	if res.Source == nil {
		t.Fatal("expected source to be set")
	}
	if res.Source.Type != constants.TypeURI || res.Source.Value != parsed.Formatted {
		t.Errorf("expected source to be %s: %s, got %s: %s", constants.TypeURI, parsed.Formatted, res.Source.Type, res.Source.Value)
	}
}
