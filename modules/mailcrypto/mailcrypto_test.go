package mailcrypto

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/schema"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/preflightcheck"
	"cdua-org/ReconSR/modules/utils/resolver"
)

func TestMailCryptoCapabilities(t *testing.T) {
	m := &module{}

	originalDisableMailcryptoBruteForce := resolver.DisableMailcryptoBruteForce
	t.Cleanup(func() {
		resolver.DisableMailcryptoBruteForce = originalDisableMailcryptoBruteForce
	})

	resolver.DisableMailcryptoBruteForce = true
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetOpenpgpkey) {
		t.Error("expected get_openpgpkey in capabilities")
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSmimea) {
		t.Error("expected get_smimea in capabilities")
	}

	if !slices.Contains(caps.Functions, constants.FuncPreflightDNS) {
		t.Error("expected preflight_dns in capabilities")
	}

	if slices.Contains(caps.InputTypes, constants.TypeDomain) {
		t.Error("unexpected domain in input types")
	}

	if slices.Contains(caps.InputTypes, constants.TypeSubdomain) {
		t.Error("unexpected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeEmail) {
		t.Error("expected email in input types")
	}

	resolver.DisableMailcryptoBruteForce = false
	caps, err = m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}
	if !slices.Contains(caps.InputTypes, constants.TypeDomain) {
		t.Error("expected domain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeSubdomain) {
		t.Error("expected subdomain in input types")
	}

	if !slices.Contains(caps.InputTypes, constants.TypeEmail) {
		t.Error("expected email in input types")
	}
}

func TestModuleMeta(t *testing.T) {
	mod := New()
	if mod.Name() != "mailcrypto" {
		t.Errorf("Expected Name() to return 'mailcrypto', got %q", mod.Name())
	}
}

func TestExec(t *testing.T) {
	mod := New()

	oldResolveRecord := resolveRecord
	resolveRecord = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecord = oldResolveRecord }()

	oldPreflight := preflightCheckFunc
	preflightCheckFunc = func(_ context.Context, _ string) error {
		return nil
	}
	defer func() { preflightCheckFunc = oldPreflight }()

	tests := []struct {
		name      string
		target    string
		functions []string
	}{
		{
			name:      "unsupported function",
			target:    "test@example.com",
			functions: []string{"unknown_func"},
		},
		{
			name:      "supported functions no at",
			target:    "example.com",
			functions: []string{constants.FuncPreflightDNS, constants.FuncGetOpenpgpkey, constants.FuncGetSmimea},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := schema.ModuleInput{
				Functions: tt.functions,
				Target:    schema.Entity{Type: constants.TypeEmail, Value: tt.target},
			}
			out, err := mod.Exec(in)
			if err != nil {
				t.Fatalf("Unexpected exec error: %v", err)
			}
			if len(out.Executions) != len(tt.functions) {
				t.Fatalf("Expected %d execution, got %d", len(tt.functions), len(out.Executions))
			}
			for i, exec := range out.Executions {
				if tt.functions[i] == "unknown_func" {
					if exec.Error == nil || *exec.Error != "unsupported function: unknown_func" {
						t.Errorf("Expected unsupported function error, got %v", exec.Error)
					}
				}
			}
		})
	}
}

func TestModule_LocalIDChaining_Preflight(t *testing.T) {
	tests := []struct {
		mockErr   error
		name      string
		wantValue string
		wantTags  []string
		wantError bool
	}{
		{
			mockErr:   nil,
			name:      "success",
			wantValue: "example.org",
			wantTags:  []string{constants.TagDNSOK},
			wantError: false,
		},
		{
			mockErr:   preflightcheck.ErrZoneBroken,
			name:      "broken zone",
			wantValue: constants.StatusBrokenDNSZone,
			wantTags:  []string{constants.TagDNSBad},
			wantError: false,
		},
		{
			mockErr:   context.DeadlineExceeded,
			name:      "other error",
			wantValue: "",
			wantTags:  nil,
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

			in := schema.Entity{Type: constants.TypeDomain, Value: "example.org"}
			res := handlePreflightDNS(context.Background(), "example.org", in)
			requireUniqueLocalIDs(t, res.Results)

			if tt.wantError {
				if res.Error == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}

			if res.Error != nil {
				t.Fatalf("unexpected error: %v", *res.Error)
			}
			if len(res.Results) == 0 {
				t.Fatalf("expected results")
			}

			found := false
			for _, r := range res.Results {
				if r.Value == tt.wantValue {
					found = true
					if !slices.Equal(r.Tags, tt.wantTags) {
						t.Errorf("expected tags %v, got %v", tt.wantTags, r.Tags)
					}
				}
			}
			if !found {
				t.Errorf("expected to find result with value %v", tt.wantValue)
			}
		})
	}
}
