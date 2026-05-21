package modutil

import (
	"testing"

	"cdua-org/ReconSR/schema"
)

func TestBuildLocalID(t *testing.T) {
	tests := []struct {
		name       string
		source     *schema.EntityRef
		entityType string
		value      string
		expected   string
	}{
		{
			name:       "nil source",
			source:     nil,
			entityType: "domain",
			value:      "example.com",
			expected:   "domain|example.com",
		},
		{
			name:       "source with empty LocalID",
			source:     &schema.EntityRef{Type: "ip", Value: "1.1.1.1"},
			entityType: "port",
			value:      "443",
			expected:   "port|443",
		},
		{
			name:       "source with LocalID",
			source:     &schema.EntityRef{LocalID: "ipv4|1.1.1.1"},
			entityType: "port",
			value:      "443",
			expected:   "ipv4|1.1.1.1|port|443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildLocalID(tt.source, tt.entityType, tt.value)
			if got != tt.expected {
				t.Errorf("BuildLocalID() = %v, want %v", got, tt.expected)
			}
		})
	}
}
