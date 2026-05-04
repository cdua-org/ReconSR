package modutil

import (
	"errors"
	"testing"
)

func TestNewExecution(t *testing.T) {
	exec := NewExecution("get_ns")

	if exec.Function != "get_ns" {
		t.Errorf("Function = %q, want %q", exec.Function, "get_ns")
	}
	if exec.Results == nil {
		t.Fatal("Results is nil, want non-nil empty slice")
	}
	if len(exec.Results) != 0 {
		t.Errorf("len(Results) = %d, want 0", len(exec.Results))
	}
	if exec.Error != nil {
		t.Errorf("Error = %v, want nil", exec.Error)
	}
	if exec.RawData != "" {
		t.Errorf("RawData = %q, want empty", exec.RawData)
	}
}

func TestSetError(t *testing.T) {
	exec := NewExecution("get_caa")
	SetError(&exec, "caa lookup failed: %v", errors.New("timeout"))

	if exec.Error == nil {
		t.Fatal("Error is nil after SetError")
	}
	want := "caa lookup failed: timeout"
	if *exec.Error != want {
		t.Errorf("Error = %q, want %q", *exec.Error, want)
	}
}

func TestSetRawFromBytes_NonEmpty(t *testing.T) {
	exec := NewExecution("get_ip")
	SetRawFromBytes(&exec, []byte(`{"Answer":[]}`))

	if exec.RawData != `{"Answer":[]}` {
		t.Errorf("RawData = %q, want %q", exec.RawData, `{"Answer":[]}`)
	}
}

func TestSetRawFromBytes_Empty(t *testing.T) {
	exec := NewExecution("get_ip")
	SetRawFromBytes(&exec, nil)

	if exec.RawData != "" {
		t.Errorf("RawData = %q, want empty", exec.RawData)
	}

	SetRawFromBytes(&exec, []byte{})
	if exec.RawData != "" {
		t.Errorf("RawData = %q, want empty after empty slice", exec.RawData)
	}
}

func TestSetRawFallback_PrefersBytes(t *testing.T) {
	exec := NewExecution("get_ns")
	SetRawFallback(&exec, []byte("raw-data"), []string{"a", "b"}, ", ")

	if exec.RawData != "raw-data" {
		t.Errorf("RawData = %q, want %q", exec.RawData, "raw-data")
	}
}

func TestSetRawFallback_FallsBackToRecords(t *testing.T) {
	exec := NewExecution("get_ns")
	SetRawFallback(&exec, nil, []string{"ns1.example.com", "ns2.example.com"}, ", ")

	want := "ns1.example.com, ns2.example.com"
	if exec.RawData != want {
		t.Errorf("RawData = %q, want %q", exec.RawData, want)
	}
}

func TestSetRawFallback_BothEmpty(t *testing.T) {
	exec := NewExecution("get_ns")
	SetRawFallback(&exec, nil, nil, ", ")

	if exec.RawData != "" {
		t.Errorf("RawData = %q, want empty", exec.RawData)
	}
}
