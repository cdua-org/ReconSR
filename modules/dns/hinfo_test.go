package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestGetHINFOData(t *testing.T) {
	origResolve := resolveRecordFunc
	defer func() { resolveRecordFunc = origResolve }()

	tests := []struct {
		name       string
		domain     string
		mockErr    error
		mockRec    []string
		mockRaw    []byte
		wantResult int
		wantErr    bool
	}{
		{
			name:       "hinfo_success",
			domain:     "peaches.example",
			mockErr:    nil,
			mockRec:    []string{"\"INTEL\" \"UNIX\""},
			mockRaw:    []byte("raw"),
			wantResult: 3,
			wantErr:    false,
		},
		{
			name:       "hinfo_resolve_error",
			domain:     "plums.example",
			mockErr:    errors.New("mock dns error"),
			mockRec:    nil,
			mockRaw:    nil,
			wantResult: 0,
			wantErr:    true,
		},
		{
			name:       "invalid record",
			domain:     "mangoes.example",
			mockErr:    nil,
			mockRec:    []string{"invalid"},
			mockRaw:    []byte("raw"),
			wantResult: 0,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				return tt.mockRec, tt.mockRaw, tt.mockErr
			}

			gen := modutil.NewLocalIDGenerator()
			exec := getHINFOData(context.Background(), tt.domain, gen)

			if (exec.Error != nil) != tt.wantErr {
				t.Errorf("getHINFOData() error = %v, wantErr %v", exec.Error, tt.wantErr)
			}
			if len(exec.Results) != tt.wantResult {
				t.Errorf("getHINFOData() results count = %d, want %d", len(exec.Results), tt.wantResult)
			}
		})
	}
}

func TestHINFOCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetHINFO) {
		t.Error("expected get_hinfo in capabilities")
	}
}

func TestBuildHINFOResults(t *testing.T) {
	parsed := &dnsutils.HINFORecord{
		CPU:       "INTEL",
		OS:        "UNIX",
		Formatted: "\"INTEL\" \"UNIX\"",
	}
	source := &schema.EntityRef{Type: constants.TypeHINFO, Value: parsed.Formatted}

	results := buildHINFOResults(parsed, source, modutil.NewLocalIDGenerator())

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Source == nil {
			t.Fatalf("expected source to be set for %s", res.Value)
		}
		if res.Source.Type != constants.TypeHINFO || res.Source.Value != parsed.Formatted {
			t.Errorf("expected source to be %s: %s, got %s: %s", constants.TypeHINFO, parsed.Formatted, res.Source.Type, res.Source.Value)
		}
	}
}
