package dns

import (
	"context"
	"net"
	"testing"
)

func TestDefaultLookups(t *testing.T) {
	ctx := context.Background()
	r := net.DefaultResolver

	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "ValidDomain_ExampleCom",
			target: "deps1.example.com",
		},
		{
			name:   "ValidDomain_ExampleNet",
			target: "deps2.example.net",
		},
		{
			name:   "InvalidDomain_NonExistent",
			target: "invalid.domain.example.nonexistent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cname, err := defaultLookupCNAME(ctx, r, tt.target)
			t.Logf("CNAME: %s, err: %v", cname, err)

			ns, err := defaultLookupNS(ctx, r, tt.target)
			t.Logf("NS: %v, err: %v", ns, err)

			mx, err := defaultLookupMX(ctx, r, tt.target)
			t.Logf("MX: %v, err: %v", mx, err)

			txt, err := defaultLookupTXT(ctx, r, tt.target)
			t.Logf("TXT: %v, err: %v", txt, err)

			srvCname, srvs, err := defaultLookupSRV(ctx, r, "sip", "tcp", tt.target)
			t.Logf("SRV CNAME: %s, SRVs: %v, err: %v", srvCname, srvs, err)
		})
	}
}
