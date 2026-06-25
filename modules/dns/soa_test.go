package dns

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestBuildSOAPrimaryNSResultSkipsInvalidAndNormalizes(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "ns1.example.com. admin.example.com. 2025010101 3600 900 604800 86400"}
	result := buildSOAPrimaryNSResult("NS1.EXAMPLE.COM.", "primary.soa.example.com", soaRef, modutil.NewLocalIDGenerator())
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

	if result.Source != soaRef {
		t.Fatal("expected source reference")
	}

	if buildSOAPrimaryNSResult(".bad.example.com.", "primary.soa.example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected invalid primary NS to be skipped")
	}
}

func TestBuildSOAPrimaryNSResultSelfReferential(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "soa_record"}
	if buildSOAPrimaryNSResult("example.com.", "example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected self-referential primary NS to be skipped")
	}
}

func TestBuildSOAResponsibleEmailResultSkipsInvalidAndUsesValidatedType(t *testing.T) {
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: "ns2.example.net. hostmaster.example.net. 2025020101 7200 1800 1209600 3600"}
	result := buildSOAResponsibleEmailResult(`"john".example.com.`, "responsible.soa.example.com", soaRef, modutil.NewLocalIDGenerator())
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

	if result.Source != soaRef {
		t.Fatal("expected source reference")
	}

	if buildSOAResponsibleEmailResult("bad..example.com.", "responsible.soa.example.com", soaRef, modutil.NewLocalIDGenerator()) != nil {
		t.Fatal("expected invalid responsible email to be skipped")
	}
}

func TestGetSOAData(t *testing.T) {
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
			name:          "successful lookup",
			target:        "getsoa.example.com",
			mockRecords:   []string{"ns1.getsoa.example.com. admin.getsoa.example.com. 2025010101 3600 900 604800 86400"},
			expectedCount: 4,
			expectError:   false,
		},
		{
			mockError:     nil,
			name:          "empty response",
			target:        "empty.getsoa.example.net",
			mockRecords:   []string{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "lookup error",
			target:        "error.getsoa.example.org",
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

			execution := getSOAData(context.Background(), tt.target, modutil.NewLocalIDGenerator())

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
