package modutil

import "sync/atomic"

// LocalIDGenerator generates sequential integer LocalIDs to uniquely identify
// entities within a single module execution (exec.Results slice).
// It starts from 1 and increments by 1 for each new ID, as required by the core system.
type LocalIDGenerator struct {
	seq atomic.Int32
}

// NewLocalIDGenerator creates a new LocalIDGenerator starting from sequence 1.
func NewLocalIDGenerator() *LocalIDGenerator {
	g := &LocalIDGenerator{}
	g.seq.Store(1)
	return g
}

// NextID returns the current sequential ID and increments the internal counter.
func (g *LocalIDGenerator) NextID() int {
	return int(g.seq.Add(1) - 1)
}
