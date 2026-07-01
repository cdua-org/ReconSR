package dnsutils

import (
	"testing"
)

func TestParseSPF(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []SPFEntity
	}{
		{
			name: "comprehensive record with all mechanisms and qualifiers",
			raw:  "v=spf1 ip4:198.51.100.0/24 +ip6:2001:db8::1 a:mail.example.com ~mx:relay.example.net -include:spf.example.org redirect=fallback.example.edu ?exists:check.example.edu ~all",
			expected: []SPFEntity{
				{Value: "198.51.100.0/24", Mechanism: "ip4", Kind: SPFEntityIP4},
				{Value: "2001:db8::1", Mechanism: "ip6", Kind: SPFEntityIP6},
				{Value: "mail.example.com", Mechanism: "a", Kind: SPFEntityDomain},
				{Value: "relay.example.net", Mechanism: "mx", Kind: SPFEntityDomain},
				{Value: "spf.example.org", Mechanism: "include", Kind: SPFEntityDomain},
				{Value: "fallback.example.edu", Mechanism: "redirect", Kind: SPFEntityDomain},
				{Value: "check.example.edu", Mechanism: "exists", Kind: SPFEntityDomain},
			},
		},
		{
			name: "trailing dot on domain stripped",
			raw:  "v=spf1 include:gateway.example.com. ~all",
			expected: []SPFEntity{
				{Value: "gateway.example.com", Mechanism: "include", Kind: SPFEntityDomain},
			},
		},
		{
			name: "ip6 with CIDR",
			raw:  "v=spf1 ip6:2001:db8:abcd::/48 -all",
			expected: []SPFEntity{
				{Value: "2001:db8:abcd::/48", Mechanism: "ip6", Kind: SPFEntityIP6},
			},
		},
		{
			name:     "not an SPF record",
			raw:      "v=DKIM1; k=rsa; p=MIGfMA0",
			expected: nil,
		},
		{
			name:     "empty SPF record",
			raw:      "v=spf1 -all",
			expected: nil,
		},
		{
			name:     "invalid ip skipped",
			raw:      "v=spf1 ip4:notanip -all",
			expected: nil,
		},
		{
			name:     "empty mechanism value skipped",
			raw:      "v=spf1 ip4: ip6: include: mx: -all",
			expected: nil,
		},
		{
			name: "mixed case SPF prefix",
			raw:  "V=SPF1 IP4:192.0.2.10 REDIRECT=UPPER.EXAMPLE.COM -all",
			expected: []SPFEntity{
				{Value: "192.0.2.10", Mechanism: "ip4", Kind: SPFEntityIP4},
				{Value: "UPPER.EXAMPLE.COM", Mechanism: "redirect", Kind: SPFEntityDomain},
			},
		},
		{
			name: "a mechanism with CIDR",
			raw:  "v=spf1 a:web.example.com/24 -all",
			expected: []SPFEntity{
				{Value: "web.example.com", Mechanism: "a", Kind: SPFEntityDomain},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSPF(tt.raw)
			if len(got) != len(tt.expected) {
				t.Fatalf("ParseSPF() returned %d entities, want %d\ngot: %+v", len(got), len(tt.expected), got)
			}
			for i, want := range tt.expected {
				if got[i].Value != want.Value {
					t.Errorf("entity[%d].Value = %q, want %q", i, got[i].Value, want.Value)
				}
				if got[i].Mechanism != want.Mechanism {
					t.Errorf("entity[%d].Mechanism = %q, want %q", i, got[i].Mechanism, want.Mechanism)
				}
				if got[i].Kind != want.Kind {
					t.Errorf("entity[%d].Kind = %d, want %d", i, got[i].Kind, want.Kind)
				}
			}
		})
	}
}
