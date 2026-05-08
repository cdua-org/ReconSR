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
			input:    "amber",
			expected: "amber",
		},
		{
			name:     "list of strings",
			input:    []any{"river", "stone"},
			expected: "river, stone",
		},
		{
			name:     "list with empty strings",
			input:    []any{"maple", "", "cedar"},
			expected: "maple, cedar",
		},
		{
			name:     "list with non-strings",
			input:    []any{"falcon", 123, "otter"},
			expected: "falcon, otter",
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
