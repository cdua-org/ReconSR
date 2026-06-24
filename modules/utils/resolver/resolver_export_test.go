package resolver

import (
	"testing"
)

func TestGetPlainServers_ReturnsNonEmptyCopy(t *testing.T) {
	servers := GetPlainServers()
	if len(servers) == 0 {
		t.Fatal("GetPlainServers returned empty slice")
	}

	original := make([]string, len(servers))
	copy(original, servers)

	servers[0] = "mutated.example.invalid"

	fresh := GetPlainServers()
	if fresh[0] == "mutated.example.invalid" {
		t.Error("GetPlainServers returned a reference instead of a copy; mutation propagated to the original pool")
	}
	if fresh[0] != original[0] {
		t.Errorf("GetPlainServers first element changed: got %q, want %q", fresh[0], original[0])
	}
}

func TestPlainStartIndex_Increments(t *testing.T) {
	first := PlainStartIndex()
	second := PlainStartIndex()
	third := PlainStartIndex()

	if second != first+1 {
		t.Errorf("PlainStartIndex did not increment: first=%d, second=%d", first, second)
	}
	if third != second+1 {
		t.Errorf("PlainStartIndex did not increment: second=%d, third=%d", second, third)
	}
}

func TestGetPlainServers_LengthMatchesPool(t *testing.T) {
	servers := GetPlainServers()
	if len(servers) < 2 {
		t.Errorf("expected at least 2 plain servers, got %d", len(servers))
	}
}
