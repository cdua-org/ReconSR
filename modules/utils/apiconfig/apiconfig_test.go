package apiconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetKey(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func(mockPath string)
		serviceName  string
		expectedKey  string
		expectedFile bool
	}{
		{
			name: "initial creation writes default and returns empty Shodan",
			setupMock: func(_ string) {
			},
			serviceName:  "Shodan",
			expectedKey:  "",
			expectedFile: true,
		},
		{
			name: "initial creation writes default and returns empty HackerTarget",
			setupMock: func(_ string) {
			},
			serviceName:  "HackerTarget",
			expectedKey:  "",
			expectedFile: true,
		},
		{
			name: "parsing existing data with valid key",
			setupMock: func(mockPath string) {
				content := []byte("[Keys]\nShodan=test_key_123\n")
				err := os.WriteFile(mockPath, content, 0o600)
				if err != nil {
					t.Fatalf("failed to setup mock file: %v", err)
				}
			},
			serviceName:  "Shodan",
			expectedKey:  "test_key_123",
			expectedFile: true,
		},
		{
			name: "missing key returns empty string",
			setupMock: func(mockPath string) {
				content := []byte("[Keys]\nShodan=test_key_123\n")
				err := os.WriteFile(mockPath, content, 0o600)
				if err != nil {
					t.Fatalf("failed to setup mock file: %v", err)
				}
			},
			serviceName:  "UnknownService",
			expectedKey:  "",
			expectedFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			mockPath := filepath.Join(tempDir, "keys.txt")

			resetForTest(mockPath)

			if tt.setupMock != nil {
				tt.setupMock(mockPath)
			}

			got := GetKey(tt.serviceName)
			if got != tt.expectedKey {
				t.Errorf("GetKey(%q) = %q, want %q", tt.serviceName, got, tt.expectedKey)
			}

			if tt.expectedFile {
				if _, err := os.Stat(mockPath); os.IsNotExist(err) {
					t.Errorf("expected config file %q to exist, but it doesn't", mockPath)
				}
			}
		})
	}
}
