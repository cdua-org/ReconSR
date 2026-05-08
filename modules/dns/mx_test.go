package dns

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
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
			if !tt.wantErr && !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("parseMX() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestBuildMXHostResult(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantValue string
		wantOK    bool
		wantOOS   bool
	}{
		{
			name:      "valid host gets normalized",
			host:      "MAIL.EXAMPLE.COM",
			wantOK:    true,
			wantValue: "mail.example.com",
			wantOOS:   false,
		},
		{
			name:   "invalid host is skipped",
			host:   "bad host",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := buildMXHostResult(tt.host, "host.mx.example.com")
			if ok != tt.wantOK {
				t.Fatalf("buildMXHostResult() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if result.Type != constants.TypeMXHost {
				t.Fatalf("buildMXHostResult() type = %q, want %q", result.Type, constants.TypeMXHost)
			}
			if result.Value != tt.wantValue {
				t.Fatalf("buildMXHostResult() value = %q, want %q", result.Value, tt.wantValue)
			}
			if result.OutOfScope != tt.wantOOS {
				t.Fatalf("buildMXHostResult() out_of_scope = %v, want %v", result.OutOfScope, tt.wantOOS)
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
	res := getMXData(context.Background(), "example.com")

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
