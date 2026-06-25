package dns

import (
	"context"
	"errors"
	"net"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/schema"
)

func TestModuleName(t *testing.T) {
	mod := New()
	if name := mod.Name(); name != "dns" {
		t.Errorf("expected module name to be 'dns', got %q", name)
	}
}

func TestExec_UnsupportedFunction(t *testing.T) {
	mod := New()
	in := schema.ModuleInput{
		Functions: []string{"unknown_func"},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "example.org",
		},
	}
	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	exec := out.Executions[0]
	if exec.Error == nil || *exec.Error != "unsupported function: unknown_func" {
		t.Errorf("expected unsupported function error, got %v", exec.Error)
	}
}

func TestExec_HandlersAndOSINT(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return []string{"0 issue \"ca.example.net\""}, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	mod := New()

	in := schema.ModuleInput{
		Functions: []string{constants.FuncGetCAA},
		Target: schema.Entity{
			Type:  constants.TypeDomain,
			Value: "test1.example",
		},
	}

	out, err := mod.Exec(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(out.Executions))
	}
	res := out.Executions[0]
	foundAlive := false
	for _, r := range res.Results {
		if len(r.Tags) > 0 && r.Tags[0] == constants.TagAlive {
			foundAlive = true
			break
		}
	}
	if !foundAlive {
		t.Errorf("expected ALIVE tag in one of the results, got %v", res.Results)
	}
}

func TestHandlePreflightDNS(t *testing.T) {
	tests := []struct {
		mockErr   error
		name      string
		wantValue string
		wantTags  []string
		wantError bool
	}{
		{
			name:      "success",
			mockErr:   nil,
			wantValue: "test.example.org",
			wantTags:  []string{constants.TagDNSOK},
		},
		{
			name:      "broken zone",
			mockErr:   preflightcheck.ErrZoneBroken,
			wantError: false,
			wantValue: constants.StatusBrokenDNSZone,
			wantTags:  []string{constants.TagDNSBad},
		},
		{
			name:      "other error",
			mockErr:   errors.New("generic error"),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPreflight := preflightCheckFunc
			preflightCheckFunc = func(_ context.Context, _ string) error {
				return tt.mockErr
			}
			defer func() { preflightCheckFunc = oldPreflight }()

			mod := New()
			in := schema.ModuleInput{
				Functions: []string{constants.FuncPreflightDNS},
				Target: schema.Entity{
					Type:  constants.TypeDomain,
					Value: "test.example.org",
				},
			}
			out, err := mod.Exec(in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			res := out.Executions[0]

			if tt.wantError {
				if res.Error == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if res.Error != nil {
				t.Errorf("unexpected error: %v", *res.Error)
			}
			if len(res.Results) == 0 {
				t.Fatal("expected results, got 0")
			}
			if res.Results[0].Value != tt.wantValue {
				t.Errorf("expected value %q, got %q", tt.wantValue, res.Results[0].Value)
			}
			if len(res.Results[0].Tags) > 0 && res.Results[0].Tags[0] != tt.wantTags[0] {
				t.Errorf("expected tag %v, got %v", tt.wantTags, res.Results[0].Tags)
			}
		})
	}
}

func TestApplyOSINTTags(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	target := schema.Entity{Type: constants.TypeDomain, Value: "test.example.net"}

	exec1 := modutil.NewExecution("untrusted")
	applyOSINTTags("untrusted", target, &exec1, gen)
	if len(exec1.Results) != 0 {
		t.Error("expected no results for untrusted function")
	}

	exec2 := modutil.NewExecution(constants.FuncGetIP)
	exec2.Results = append(exec2.Results, schema.ModuleResult{Value: "1.1.1.1"})
	applyOSINTTags(constants.FuncGetIP, target, &exec2, gen)
	if len(exec2.Results) != 2 || exec2.Results[1].Tags[0] != constants.TagAlive {
		t.Error("expected ALIVE tag")
	}

	exec3 := modutil.NewExecution(constants.FuncGetIP)
	errMsg := "lookup example.net: no such host"
	exec3.Error = &errMsg
	applyOSINTTags(constants.FuncGetIP, target, &exec3, gen)
	if len(exec3.Results) != 1 || exec3.Results[0].Tags[0] != constants.TagDead {
		t.Error("expected DEAD tag")
	}
}
