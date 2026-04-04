package domainsbycerts

import (
	"sort"
	"strings"
	"testing"
)

func TestFormatOutput(t *testing.T) {
	rawDomains := []string{
		"*.example.com",
		"a.example.com",
		"B.example.com",
		"a.example.com",
		"example.com",
		"notexample.com",
		"sub.notexample.com",
		"valid.sub.example.com",
	}

	target := "example.com"
	uniqueDomains := make(map[string]bool)
	var result []string

	for _, d := range rawDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(d, "*.")

		if d != "" && d != target && strings.HasSuffix(d, "."+target) {
			if !uniqueDomains[d] {
				uniqueDomains[d] = true
				result = append(result, d)
			}
		}
	}

	sort.Strings(result)

	expected := []string{"a.example.com", "b.example.com", "valid.sub.example.com"}

	if len(result) != len(expected) {
		t.Fatalf("expected %d domains, got %d", len(expected), len(result))
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("expected %q, got %q", v, result[i])
		}
	}
}
