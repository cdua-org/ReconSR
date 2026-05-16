package dnsutils

import "testing"

func TestParseNSEC(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"valid_nsec", "next.example.com. A AAAA RRSIG NSEC", "next.example.com."},
		{"empty_nsec", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseNSEC(tt.data); got != tt.expected {
				t.Errorf("ParseNSEC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseNSEC3(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"valid_nsec3", "1 0 10 AABBCCDD EEFF00112233 A RRSIG", "EEFF00112233"},
		{"short_nsec3", "1 0 10 AABBCCDD", ""},
		{"empty_nsec3", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseNSEC3(tt.data); got != tt.expected {
				t.Errorf("ParseNSEC3() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExtractNSEC3Hash(t *testing.T) {
	tests := []struct {
		name       string
		recordName string
		expected   string
	}{
		{"valid_hash", "0p9mhaveqvm6t7v8pon2iu430l8kcmpo.example.com.", "0p9mhaveqvm6t7v8pon2iu430l8kcmpo"},
		{"no_dots_hash", "hashonly", "hashonly"},
		{"empty_hash", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractNSEC3Hash(tt.recordName); got != tt.expected {
				t.Errorf("ExtractNSEC3Hash() = %v, want %v", got, tt.expected)
			}
		})
	}
}
