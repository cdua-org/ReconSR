package dns

import (
	"context"
	"errors"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestModuleCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(caps.Functions) == 0 {
		t.Fatal("expected functions, got none")
	}

	if !slices.Contains(caps.Functions, constants.FuncGetIP) {
		t.Error("expected get_ip in capabilities")
	}
}

func TestExecUnsupported(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Target:    schema.Entity{Type: constants.TypeDomain, Value: "test.invalid"},
		Functions: []string{"unknown_func"},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("expected no error from Exec, got: %v", err)
	}

	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}

	if out.Executions[0].Error == nil {
		t.Error("expected error for unsupported function")
	}
}

func TestGetIPData(t *testing.T) {
	origResolve := resolveIPFunc
	defer func() { resolveIPFunc = origResolve }()

	tests := []struct {
		name       string
		domain     string
		mockErr    error
		mockIPs    []string
		mockRaw    []byte
		wantResult int
		wantErr    bool
	}{
		{
			name:       "ip_success_records",
			domain:     "cherry-ip.example",
			mockErr:    nil,
			mockIPs:    []string{"192.0.2.1", "2001:db8::1"},
			mockRaw:    []byte("raw"),
			wantResult: 2,
			wantErr:    false,
		},
		{
			name:       "ip_resolve_error",
			domain:     "berry-ip.example",
			mockErr:    errors.New("mock dns error"),
			mockIPs:    nil,
			mockRaw:    nil,
			wantResult: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveIPFunc = func(_ context.Context, _ string) ([]string, []byte, error) {
				return tt.mockIPs, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getIPData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getIPData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getIPData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}
