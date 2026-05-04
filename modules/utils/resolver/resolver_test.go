package resolver

import (
	"testing"
)

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
		isIPv4   bool
		isErr    bool
	}{
		{"8.8.8.8", "8.8.8.8", true, false},
		{"93.184.216.34", "34.216.184.93", true, false},
		{"2001:4860:4860::8888", "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2", false, false},
		{"invalid", "", false, true},
	}

	for _, tt := range tests {
		rev, isIPv4, err := ReverseIP(tt.ip)
		if (err != nil) != tt.isErr {
			t.Errorf("ip %q: expected error %v, got %v", tt.ip, tt.isErr, err)
		}
		if rev != tt.expected {
			t.Errorf("ip %q: expected %q, got %q", tt.ip, tt.expected, rev)
		}
		if isIPv4 != tt.isIPv4 {
			t.Errorf("ip %q: expected isIPv4 %v, got %v", tt.ip, tt.isIPv4, isIPv4)
		}
	}
}
