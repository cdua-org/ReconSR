package virustotal

import (
	"encoding/json"
	"testing"
)

func TestFormatVTInt(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
		ok       bool
	}{
		{
			name:     "float64 input",
			input:    float64(4242),
			expected: "4242",
			ok:       true,
		},
		{
			name:     "int input",
			input:    int(98765),
			expected: "98765",
			ok:       true,
		},
		{
			name:     "int64 input",
			input:    int64(1234567890123),
			expected: "1234567890123",
			ok:       true,
		},
		{
			name:     "json.Number input",
			input:    json.Number("8888"),
			expected: "8888",
			ok:       true,
		},
		{
			name:     "unsupported string",
			input:    "not a number",
			expected: "",
			ok:       false,
		},
		{
			name:     "unsupported nil",
			input:    nil,
			expected: "",
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatVTInt(tt.input)
			if ok != tt.ok {
				t.Errorf("formatVTInt() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.expected {
				t.Errorf("formatVTInt() got = %v, want %v", got, tt.expected)
			}
		})
	}
}
