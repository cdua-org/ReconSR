package apiconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetKey(t *testing.T) {
	const shodanService = "Shodan"

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
			serviceName:  shodanService,
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
			name: "initial creation writes default and returns empty VirusTotal",
			setupMock: func(_ string) {
			},
			serviceName:  "VirusTotal",
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
			serviceName:  shodanService,
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
		{
			name: "env var takes precedence over file",
			setupMock: func(mockPath string) {
				content := []byte("[Keys]\nShodan=file_key\n")
				err := os.WriteFile(mockPath, content, 0o600)
				if err != nil {
					t.Fatalf("failed to setup mock file: %v", err)
				}
				t.Setenv("RECONSR_SHODAN", "env_key")
			},
			serviceName:  shodanService,
			expectedKey:  "env_key",
			expectedFile: true,
		},
		{
			name: "env var works when file key is missing",
			setupMock: func(_ string) {
				t.Setenv("RECONSR_SHODAN", "env_key_only")
			},
			serviceName:  shodanService,
			expectedKey:  "env_key_only",
			expectedFile: true,
		},
		{
			name: "MkdirAll error triggers fallback to default config",
			setupMock: func(mockPath string) {
				invalidDir := filepath.Join(filepath.Dir(mockPath), "invalid_dir")
				if err := os.WriteFile(invalidDir, []byte("not a dir"), 0o600); err != nil {
					t.Fatalf("failed to write invalid dir file: %v", err)
				}
				resetForTest(filepath.Join(invalidDir, "keys.txt"))
			},
			serviceName:  "HackerTarget",
			expectedKey:  "",
			expectedFile: false,
		},
		{
			name: "WriteFile error triggers fallback and stderr output",
			setupMock: func(mockPath string) {
				readOnlyDir := filepath.Join(filepath.Dir(mockPath), "readonly")
				if err := os.MkdirAll(readOnlyDir, 0o500); err != nil {
					t.Fatalf("failed to mkdir read-only: %v", err)
				}
				resetForTest(filepath.Join(readOnlyDir, "keys.txt"))
			},
			serviceName:  "VirusTotal",
			expectedKey:  "",
			expectedFile: false,
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
