package whois

import (
	"testing"
)

func TestExtractTLD(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"foo.example.com", "com"},
		{"client.demo.example.org", "org"},
		{"sub.example.net", "net"},
		{"localhost", "localhost"},
		{"a.b.c.d.example", "example"},
		{"", ""},
	}

	for _, tc := range tests {
		if got := extractTLD(tc.domain); got != tc.expected {
			t.Errorf("extractTLD(%q) = %q, expected %q", tc.domain, got, tc.expected)
		}
	}
}

func TestBuildRDAPURL(t *testing.T) {
	ianaRDAPBootstrap.Do(func() {
		ianaRDAPServers = make(map[string]string)
	})
	if ianaRDAPServers == nil {
		ianaRDAPServers = make(map[string]string)
	}
	ianaRDAPServers["mocktld"] = "https://rdap.mock.example/"

	tests := []struct {
		domain   string
		expected string
	}{
		{"test.de", "https://rdap.denic.de/domain/test.de"},
		{"test.mocktld", "https://rdap.mock.example/domain/test.mocktld"},
		{"test.unknown", "https://rdap.org/domain/test.unknown"},
	}

	for _, tc := range tests {
		if got := buildRDAPURL(tc.domain); got != tc.expected {
			t.Errorf("buildRDAPURL(%q) = %q, expected %q", tc.domain, got, tc.expected)
		}
	}
}
