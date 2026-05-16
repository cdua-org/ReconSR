package dnsutils

import (
	"reflect"
	"testing"
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
			got, err := ParseSRVHost(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSRVHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseSRVHost() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}
