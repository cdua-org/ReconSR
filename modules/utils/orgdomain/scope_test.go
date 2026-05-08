package orgdomain

import (
	"strings"
	"testing"
)

func TestIsOutOfScope(t *testing.T) {
	const (
		baseDomain      = "example.com"
		baseSubdomain   = "ns1.example.com"
		altSubdomain    = "ns1.example.org"
		scopedSubdomain = "sub.example.com"
		singleLabel     = "com"
	)

	tests := []struct {
		name   string
		entity string
		target string
		want   bool
	}{
		{
			name:   "same org",
			entity: baseSubdomain,
			target: baseDomain,
			want:   false,
		},
		{
			name:   "different org",
			entity: altSubdomain,
			target: baseDomain,
			want:   true,
		},
		{
			name:   "exact match",
			entity: baseDomain,
			target: baseDomain,
			want:   false,
		},
		{
			name:   "trailing dot stripped",
			entity: baseSubdomain + ".",
			target: baseDomain + ".",
			want:   false,
		},
		{
			name:   "case insensitive",
			entity: strings.ToUpper(baseSubdomain),
			target: baseDomain,
			want:   false,
		},
		{
			name:   "empty entity",
			entity: "",
			target: baseDomain,
			want:   false,
		},
		{
			name:   "empty target",
			entity: baseSubdomain,
			target: "",
			want:   false,
		},
		{
			name:   "subdomain of target when org domain fails",
			entity: scopedSubdomain,
			target: singleLabel,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOutOfScope(tt.entity, tt.target)
			if got != tt.want {
				t.Errorf("IsOutOfScope(%q, %q) = %v, want %v", tt.entity, tt.target, got, tt.want)
			}
		})
	}
}

func TestIsEmailOutOfScope(t *testing.T) {
	const (
		baseDomain         = "example.com"
		adminEmail         = "ops@example.com"
		adminAltEmail      = "ops@example.org"
		mailSubdomainEmail = "admin@mail.example.com"
	)

	tests := []struct {
		name   string
		email  string
		target string
		want   bool
	}{
		{
			name:   "same org email",
			email:  adminEmail,
			target: baseDomain,
			want:   false,
		},
		{
			name:   "different org email",
			email:  adminAltEmail,
			target: baseDomain,
			want:   true,
		},
		{
			name:   "subdomain email",
			email:  mailSubdomainEmail,
			target: baseDomain,
			want:   false,
		},
		{
			name:   "no at sign",
			email:  "noemail",
			target: baseDomain,
			want:   false,
		},
		{
			name:   "empty email",
			email:  "",
			target: baseDomain,
			want:   false,
		},
		{
			name:   "at sign but empty domain",
			email:  "user@",
			target: baseDomain,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsEmailOutOfScope(tt.email, tt.target)
			if got != tt.want {
				t.Errorf("IsEmailOutOfScope(%q, %q) = %v, want %v", tt.email, tt.target, got, tt.want)
			}
		})
	}
}
