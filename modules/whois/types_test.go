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

func TestNormalizePhone(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  tel:+1.555.123.4567  ", "+15551234567"},
		{"phone: 1 (800) 555-0199", "+18005550199"},
		{"123", ""},
		{"+44 123 456 7890", "+441234567890"},
		{"invalid_phone_number", ""},
		{"", ""},
		{"+abc1234567890", "+1234567890"},
		{"1+2+3+4+5+6+7+8+9+0", "+1234567890"},
		{"+", ""},
		{"tel:+9876543210", "+9876543210"},
	}

	for _, tc := range tests {
		if got := normalizePhone(tc.input); got != tc.expected {
			t.Errorf("normalizePhone(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestIsPrivacyService(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"Domains By Proxy, LLC", true},
		{"Whois Privacy Protection Service, Inc.", true},
		{"Contact Privacy Inc. Customer Care", true},
		{"Super Redacted Name", true},
		{"Google LLC", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := isPrivacyService(tc.input); got != tc.expected {
			t.Errorf("isPrivacyService(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}
