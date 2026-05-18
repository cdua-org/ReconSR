package resolver

import "testing"

func TestParseOptionEmailformatLookupSubdomains(t *testing.T) {
	original := EmailformatLookupSubdomains
	defer func() {
		EmailformatLookupSubdomains = original
	}()

	initOptionMaps()
	EmailformatLookupSubdomains = false
	parseOption("EmailformatLookupSubdomains=true")
	if !EmailformatLookupSubdomains {
		t.Fatal("expected EmailformatLookupSubdomains to become true")
	}

	parseOption("EmailformatLookupSubdomains=false")
	if EmailformatLookupSubdomains {
		t.Fatal("expected EmailformatLookupSubdomains to become false")
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
		isIPv4   bool
		isErr    bool
	}{
		{"192.0.2.1", "1.2.0.192", true, false},
		{"198.51.100.2", "2.100.51.198", true, false},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2", false, false},
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
