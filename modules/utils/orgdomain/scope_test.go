package orgdomain

import "testing"

func TestIsOutOfScope(t *testing.T) {
	tests := []struct {
		name   string
		entity string
		target string
		want   bool
	}{
		{
			name:   "same org",
			entity: "ns1.example.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "different org",
			entity: "ns1.cloudflare.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "exact match",
			entity: "example.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "trailing dot stripped",
			entity: "ns1.example.com.",
			target: "example.com.",
			want:   false,
		},
		{
			name:   "case insensitive",
			entity: "NS1.Example.COM",
			target: "example.com",
			want:   false,
		},
		{
			name:   "empty entity",
			entity: "",
			target: "example.com",
			want:   false,
		},
		{
			name:   "empty target",
			entity: "ns1.example.com",
			target: "",
			want:   false,
		},
		{
			name:   "subdomain of target when org domain fails",
			entity: "sub.test",
			target: "test",
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
	tests := []struct {
		name   string
		email  string
		target string
		want   bool
	}{
		{
			name:   "same org email",
			email:  "admin@example.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "different org email",
			email:  "admin@external.com",
			target: "example.com",
			want:   true,
		},
		{
			name:   "subdomain email",
			email:  "admin@mail.example.com",
			target: "example.com",
			want:   false,
		},
		{
			name:   "no at sign",
			email:  "noemail",
			target: "example.com",
			want:   false,
		},
		{
			name:   "empty email",
			email:  "",
			target: "example.com",
			want:   false,
		},
		{
			name:   "at sign but empty domain",
			email:  "user@",
			target: "example.com",
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
