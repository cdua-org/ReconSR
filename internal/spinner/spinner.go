// Package spinner provides console animation utilities.
package spinner

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Spinner encapsulates the background rendering state.
type Spinner struct {
	out        io.Writer
	completed  *atomic.Int32
	timeSource func() time.Time
	label      string
	frames     []string
	interval   time.Duration
	total      int
}

// Option allows dependency injection for visual settings.
type Option func(*Spinner)

// WithWriter isolates stdout for concurrent tests.
func WithWriter(w io.Writer) Option {
	return func(s *Spinner) {
		s.out = w
	}
}

// WithInterval fine-tunes visual refresh rates.
func WithInterval(d time.Duration) Option {
	return func(s *Spinner) {
		s.interval = d
	}
}

// WithTimeSource enables deterministic elapsed time testing.
func WithTimeSource(f func() time.Time) Option {
	return func(s *Spinner) {
		s.timeSource = f
	}
}

// Start initiates the non-blocking UI update loop. Returning the closer ensures clean termination before subsequent stdout writes.
func Start(ctx context.Context, label string, completed *atomic.Int32, total int, opts ...Option) func() {
	s := &Spinner{
		label:      label,
		total:      total,
		completed:  completed,
		out:        os.Stderr,
		frames:     []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		interval:   150 * time.Millisecond,
		timeSource: time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		s.run(ctx)
	}()

	return func() {
		cancel()
		<-done
	}
}

func (s *Spinner) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	start := s.timeSource()
	i := 0

	for {
		select {
		case <-ctx.Done():
			s.printFrame(start, i)
			_, err := fmt.Fprintln(s.out)
			_ = err
			return
		case <-ticker.C:
			s.printFrame(start, i)
			i++
		}
	}
}

func (s *Spinner) printFrame(start time.Time, i int) {
	c := int32(0)
	if s.completed != nil {
		c = s.completed.Load()
	}
	elapsed := s.timeSource().Sub(start).Round(time.Second)
	_, err := fmt.Fprintf(s.out, "\r\033[K%s %s [%d/%d] (Elapsed: %s)", s.frames[i%len(s.frames)], s.label, c, s.total, elapsed)
	_ = err
}
