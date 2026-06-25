package dns

import (
	"context"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestGetSVCBData(t *testing.T) {
	tests := []struct {
		mockError     error
		name          string
		target        string
		mockRecords   []string
		expectedCount int
	}{
		{
			mockError:     nil,
			name:          "svcb lookup success",
			target:        "getsvcb.example.com",
			mockRecords:   []string{"1 svc.getsvcb.example.com. ipv4hint=192.0.2.1 ipv6hint=::1 alpn=h2,h3 ech=YmFzZTY0"},
			expectedCount: 10,
		},
		{
			mockError:     nil,
			name:          "svcb lookup unparsed",
			target:        "unparsed.getsvcb.example.net",
			mockRecords:   []string{"invalid_svcb_record"},
			expectedCount: 2,
		},
		{
			mockError:     nil,
			name:          "svcb lookup empty",
			target:        "empty.getsvcb.example.org",
			mockRecords:   []string{},
			expectedCount: 0,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "svcb lookup err",
			target:        "error.getsvcb.example.com",
			mockRecords:   nil,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origResolveRecordFunc := resolveRecordFunc
			defer func() { resolveRecordFunc = origResolveRecordFunc }()

			resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
				if tt.mockError != nil {
					return nil, nil, tt.mockError
				}
				return tt.mockRecords, []byte("mock raw data"), nil
			}

			execution := getSVCBData(context.Background(), tt.target, modutil.NewLocalIDGenerator())

			if execution.Error != nil {
				t.Errorf("unexpected error: %v", *execution.Error)
			}
			if len(execution.Results) != tt.expectedCount {
				t.Errorf("expected %d results, got %d", tt.expectedCount, len(execution.Results))
			}
		})
	}
}

func TestSVCBCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetSVCB) {
		t.Error("expected get_svcb in capabilities")
	}
}
