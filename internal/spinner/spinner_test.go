package spinner

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSpinner_Basic(t *testing.T) {
	var buf bytes.Buffer
	var completed atomic.Int32

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stop := Start(ctx, "Test...", &completed, 10,
		WithWriter(&buf),
		WithInterval(5*time.Millisecond),
		WithTimeSource(func() time.Time {
			return time.Time{}
		}),
	)

	completed.Add(2)
	time.Sleep(15 * time.Millisecond)
	stop()

	output := buf.String()
	if !strings.Contains(output, "Test... [2/10] (Elapsed: 0s)") {
		t.Errorf("expected output to contain 'Test... [2/10] (Elapsed: 0s)', got %q", output)
	}
	if !strings.HasSuffix(output, "\n") {
		t.Errorf("expected output to end with newline")
	}
}

func TestSpinner_NilCompleted(t *testing.T) {
	var buf bytes.Buffer

	ctx := t.Context()
	stop := Start(ctx, "Nil...", nil, 5,
		WithWriter(&buf),
		WithInterval(5*time.Millisecond),
	)

	time.Sleep(15 * time.Millisecond)
	stop()

	output := buf.String()
	if !strings.Contains(output, "Nil... [0/5]") {
		t.Errorf("expected output to handle nil completed safely, got %q", output)
	}
}

func TestSpinner_ContextCancel(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())

	stop := Start(ctx, "Ctx...", nil, 1, WithWriter(&buf))

	cancel()
	stop()

	output := buf.String()
	if !strings.Contains(output, "Ctx...") {
		t.Errorf("expected output even on context cancel, got %q", output)
	}
}
