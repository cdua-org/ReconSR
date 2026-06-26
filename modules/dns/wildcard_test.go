package dns

import (
	"context"
	"errors"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestCheckWildcard(t *testing.T) {
	tests := []struct {
		mockError     error
		name          string
		target        string
		mockRecords   []string
		expectedCount int
		expectError   bool
		failRandRead  bool
	}{
		{
			mockError:     nil,
			name:          "wildcard lookup success",
			target:        "getwildcard.example.com",
			mockRecords:   []string{"192.0.2.1"},
			expectedCount: 1,
			expectError:   false,
		},
		{
			mockError:     nil,
			name:          "wildcard lookup empty",
			target:        "empty.getwildcard.example.net",
			mockRecords:   []string{},
			expectedCount: 0,
			expectError:   false,
		},
		{
			mockError:     context.DeadlineExceeded,
			name:          "wildcard lookup err",
			target:        "error.getwildcard.example.org",
			mockRecords:   nil,
			expectedCount: 0,
			expectError:   true,
		},
		{
			name:         "rand read failure",
			target:       "rand.getwildcard.example.com",
			expectError:  true,
			failRandRead: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origResolveIPFunc := resolveIPFunc
			origRandReadFunc := randReadFunc
			defer func() {
				resolveIPFunc = origResolveIPFunc
				randReadFunc = origRandReadFunc
			}()

			if tt.failRandRead {
				randReadFunc = func(_ []byte) (int, error) {
					return 0, errors.New("entropy source unavailable")
				}
			}

			resolveIPFunc = func(_ context.Context, _ string) ([]string, []byte, error) {
				if tt.mockError != nil {
					return nil, nil, tt.mockError
				}
				return tt.mockRecords, []byte("mock raw data"), nil
			}

			execution := checkWildcard(context.Background(), tt.target, modutil.NewLocalIDGenerator())

			if tt.expectError {
				if execution.Error == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if execution.Error != nil {
					t.Errorf("unexpected error: %v", *execution.Error)
				}
				if len(execution.Results) != tt.expectedCount {
					t.Errorf("expected %d results, got %d", tt.expectedCount, len(execution.Results))
				}
			}
		})
	}
}

func TestWildcardCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncCheckWildcard) {
		t.Error("expected check_wildcard in capabilities")
	}
}
