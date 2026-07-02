package ip_metadata

import (
	"context"
	"net"
	"testing"
)

func TestDefaultLookupTXT(t *testing.T) {
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
			txt, err := defaultLookupTXT(ctx, r, tt.target)
			t.Logf("TXT: %v, err: %v", txt, err)
		})
	}
}

func TestDefaultLookupHost(t *testing.T) {
	ctx := context.Background()
	r := net.DefaultResolver

	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "ValidDomain_ExampleCom",
			target: "deps3.example.com",
		},
		{
			name:   "InvalidDomain_NonExistent",
			target: "invalid.domain.example.nonexistent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := defaultLookupHost(ctx, r, tt.target)
			t.Logf("IPs: %v, err: %v", ips, err)
		})
	}
}
