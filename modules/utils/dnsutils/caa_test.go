package dnsutils

import (
	"testing"
)

func TestDecodeHexCAA(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "valid hex encoded issue",
			input:    `\# 21 00 05 69 73 73 75 65 63 61 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d`,
			expected: `0 issue "ca.example.com"`,
			wantErr:  false,
		},
		{
			name:     "invalid hex",
			input:    `\# 21 zz`,
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeHexCAA(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeHexCAA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("DecodeHexCAA() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestParseCAA(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantNorm  string
		wantTag   string
		wantVal   string
		wantMatch bool
	}{
		{
			name:      "issue basic",
			input:     `0 issue "ca.example.net"`,
			wantNorm:  `0 issue "ca.example.net"`,
			wantTag:   "issue",
			wantVal:   "ca.example.net",
			wantMatch: true,
		},
		{
			name:      "iodef email",
			input:     `0 iodef "mailto:Security@Example.COM"`,
			wantNorm:  `0 iodef "mailto:Security@Example.COM"`,
			wantTag:   "iodef",
			wantVal:   "mailto:Security@Example.COM",
			wantMatch: true,
		},
		{
			name:      "hex encoded issue",
			input:     `\# 21 00 05 69 73 73 75 65 63 61 2e 65 78 61 6d 70 6c 65 2e 6f 72 67`, // ca.example.org
			wantNorm:  `0 issue "ca.example.org"`,
			wantTag:   "issue",
			wantVal:   "ca.example.org",
			wantMatch: true,
		},
		{
			name:      "invalid format",
			input:     `invalid record`,
			wantNorm:  `invalid record`,
			wantTag:   "",
			wantVal:   "",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, tag, val, matched := ParseCAA(tt.input)
			if matched != tt.wantMatch {
				t.Errorf("ParseCAA() matched = %v, want %v", matched, tt.wantMatch)
			}
			if norm != tt.wantNorm {
				t.Errorf("ParseCAA() norm = %q, want %q", norm, tt.wantNorm)
			}
			if tag != tt.wantTag {
				t.Errorf("ParseCAA() tag = %q, want %q", tag, tt.wantTag)
			}
			if val != tt.wantVal {
				t.Errorf("ParseCAA() val = %q, want %q", val, tt.wantVal)
			}
		})
	}
}

func TestExtractCAAAuthority(t *testing.T) {
	if got := ExtractCAAAuthority("ca.example.net; cansignhttpexchanges=yes"); got != "ca.example.net" {
		t.Errorf("ExtractCAAAuthority() = %q", got)
	}
	if got := ExtractCAAAuthority("ca.example.org"); got != "ca.example.org" {
		t.Errorf("ExtractCAAAuthority() = %q", got)
	}
}

func TestExtractCAAIodefEmail(t *testing.T) {
	if got := ExtractCAAIodefEmail("mailto:admin@example.com"); got != "admin@example.com" {
		t.Errorf("ExtractCAAIodefEmail() = %q", got)
	}
	if got := ExtractCAAIodefEmail("mailto://admin@example.org"); got != "admin@example.org" {
		t.Errorf("ExtractCAAIodefEmail() = %q", got)
	}
	if got := ExtractCAAIodefEmail("https://example.com/abuse"); got != "" {
		t.Errorf("ExtractCAAIodefEmail() = %q", got)
	}
}
