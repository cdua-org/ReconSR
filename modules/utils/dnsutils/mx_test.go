package dnsutils

import (
	"testing"
)

func TestParseMXHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid MX record",
			input:    "10 mail.example.com.",
			expected: "mail.example.com",
		},
		{
			name:     "valid MX without trailing dot",
			input:    "20 relay.example.net",
			expected: "relay.example.net",
		},
		{
			name:    "invalid single field",
			input:   "mail.example.com.",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "dot-only host",
			input:   "10 .",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMXHost(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMXHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseMXHost() = %q, want %q", got, tt.expected)
			}
		})
	}
}
