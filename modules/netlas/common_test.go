package netlas

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestParseNetlasDomains(t *testing.T) {
	t.Parallel()

	targetRef := &schema.EntityRef{Type: constants.TypeIP, Value: "192.0.2.1"}

	tests := []struct {
		name          string
		domains       []string
		count         int
		expectedCount int
	}{
		{"Count 0", []string{"0a.example.edu", "0b.example.edu"}, 0, 0},
		{"Count Greater Than 10", []string{"11a.example.edu", "11b.example.edu"}, 11, 0},
		{"Count Within Limit", []string{"2a.example.edu", "2b.example.edu"}, 2, 2},
		{"Count 10", []string{"10a.example.edu", "10b.example.edu"}, 10, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{Function: "test"}
			gen := modutil.NewLocalIDGenerator()

			parseNetlasDomains(exec, tt.count, tt.domains, constants.TagReverseIP, targetRef, gen)

			if len(exec.Results) != tt.expectedCount {
				t.Errorf("expected %d results, got %d", tt.expectedCount, len(exec.Results))
			}
		})
	}
}

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{"ValidIPv4", "192.168.1.0/24", true},
		{"ValidIPv6", "2001:db8::/32", true},
		{"NoSlash", "192.168.1.1", false},
		{"InvalidIP", "invalid/24", false},
		{"InvalidMaskFormat", "192.168.1.0/abc", false},
		{"NegativeMask", "192.168.1.0/-1", false},
		{"MaskTooLarge", "192.168.1.0/129", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateCIDR(tt.cidr); got != tt.expected {
				t.Errorf("validateCIDR(%q) = %v, want %v", tt.cidr, got, tt.expected)
			}
		})
	}
}
