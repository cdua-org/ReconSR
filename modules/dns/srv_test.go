package dns

import (
	"context"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestBuildSRVHostResult(t *testing.T) {
	srvRef := &schema.EntityRef{Type: constants.TypeSRV, Value: "10 50 5060 sip.example.com"}

	tests := []struct {
		name      string
		host      string
		target    string
		wantValue string
		wantType  string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "valid host gets normalized",
			host:      "SIP.SRV1.EXAMPLE.COM.",
			target:    "srv1.example.com",
			wantValue: "sip.srv1.example.com",
			wantType:  constants.TypeSubdomain,
			wantOK:    true,
			wantOOS:   false,
		},
		{
			name:      "out of scope host",
			host:      "sip.external.example.org",
			target:    "srv2.example.com",
			wantValue: "sip.external.example.org",
			wantType:  constants.TypeSubdomain,
			wantOK:    true,
			wantOOS:   true,
		},
		{
			name:      "invalid host is skipped",
			host:      "invalid_host",
			target:    "srv-invalid.example.com",
			wantValue: "",
			wantOK:    false,
			wantOOS:   false,
		},
		{
			name:      "self-referential host is skipped",
			host:      "srv-self.example.com",
			target:    "srv-self.example.com",
			wantValue: "",
			wantOK:    false,
			wantOOS:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := buildSRVHostResult(tt.host, tt.target, srvRef)
			if ok != tt.wantOK {
				t.Fatalf("buildSRVHostResult() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if result.Type != tt.wantType {
				t.Fatalf("buildSRVHostResult() type = %q, want %q", result.Type, tt.wantType)
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
			if result.Source != srvRef {
				t.Fatalf("buildSRVHostResult() source = %+v, want %+v", result.Source, srvRef)
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
