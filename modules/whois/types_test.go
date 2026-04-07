// file: types_test.go

package whois

import "testing"

func TestSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "list of strings",
			input:    []any{"hello", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with empty strings",
			input:    []any{"hello", "", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with non-strings",
			input:    []any{"hello", 123, "world"},
			expected: "hello, world",
		},
		{
			name:     "invalid type",
			input:    123,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeString(tt.input); got != tt.expected {
				t.Errorf("safeString() = %v, want %v", got, tt.expected)
			}
		})
	}
}
