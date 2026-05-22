package modutil

import (
	"testing"
)

func TestLocalIDGenerator(t *testing.T) {
	gen := NewLocalIDGenerator()

	for i := 1; i <= 5; i++ {
		got := gen.NextID()
		if got != i {
			t.Errorf("NextID() = %d, want %d", got, i)
		}
	}
}
