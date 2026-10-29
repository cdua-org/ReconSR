package apiconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetKey_LocalConfig(t *testing.T) {
	tests := []struct {
		name         string
		setupMock    func(subT *testing.T, mockPath string)
		serviceName  string
		expectedKey  string
		expectedFile bool
	}{
		{
			name: "initial creation writes default and returns empty Shodan",
			setupMock: func(_ *testing.T, _ string) {
			},
			serviceName:  "Shodan",
			expectedKey:  "",
			expectedFile: true,
		},
		{
			name: "initial creation writes default and returns empty HackerTarget",
			setupMock: func(_ *testing.T, _ string) {
			},
			serviceName:  "HackerTarget",
			expectedKey:  "",
			expectedFile: true,
		},
		{
			name: "initial creation writes default and returns empty VirusTotal",
			setupMock: func(_ *testing.T, _ string) {
			},
			serviceName:  "VirusTotal",
			expectedKey:  "",
			expectedFile: true,
		},
		{
			name: "parsing existing data with valid key",
			setupMock: func(_ *testing.T, mockPath string) {
				content := []byte("[Keys]\nNetlas=netlas-test-value\n")
				err := os.WriteFile(mockPath, content, 0o600)
				if err != nil {
					t.Fatalf("failed to setup mock file: %v", err)
				}
			},
			serviceName:  "Netlas",
			expectedKey:  "netlas-test-value",
			expectedFile: true,
		},
		{
			name: "missing key returns empty string",
			setupMock: func(_ *testing.T, mockPath string) {
				content := []byte("[Keys]\nCircl=circl_key_abc\n")
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
			name: "MkdirAll error triggers fallback to default config",
			setupMock: func(subT *testing.T, mockPath string) {
				invalidDir := filepath.Join(filepath.Dir(mockPath), "invalid_dir")
				if err := os.WriteFile(invalidDir, []byte("not a dir"), 0o600); err != nil {
					subT.Fatalf("failed to write invalid dir file: %v", err)
				}
				resetForTest(filepath.Join(invalidDir, "keys.txt"), "")
			},
			serviceName:  "AbuseIPDB",
			expectedKey:  "",
			expectedFile: false,
		},
		{
			name: "WriteFile error triggers fallback and stderr output",
			setupMock: func(subT *testing.T, mockPath string) {
				readOnlyDir := filepath.Join(filepath.Dir(mockPath), "readonly")
				if err := os.MkdirAll(readOnlyDir, 0o500); err != nil {
					subT.Fatalf("failed to mkdir read-only: %v", err)
				}
				resetForTest(filepath.Join(readOnlyDir, "keys.txt"), "")
			},
			serviceName:  "Hunterio",
			expectedKey:  "",
			expectedFile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(subT *testing.T) {
			tempDir := subT.TempDir()
			mockPath := filepath.Join(tempDir, "keys.txt")

			resetForTest(mockPath, "")

			if tt.setupMock != nil {
				tt.setupMock(subT, mockPath)
			}

			got := GetKey(tt.serviceName)
			if got != tt.expectedKey {
				subT.Errorf("GetKey(%q) = %q, want %q", tt.serviceName, got, tt.expectedKey)
			}

			if tt.expectedFile {
				if _, err := os.Stat(mockPath); os.IsNotExist(err) {
					subT.Errorf("expected config file %q to exist, but it doesn't", mockPath)
				}
			}
		})
	}
}

func TestGetKey_SecretsAndEnv(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func(subT *testing.T, mockPath, secretsPath string)
		serviceName string
		expectedKey string
	}{
		{
			name: "env var takes precedence over file",
			setupMock: func(subT *testing.T, mockPath, _ string) {
				content := []byte("[Keys]\nIPinfo=file_ipinfo_key\n")
				err := os.WriteFile(mockPath, content, 0o600)
				if err != nil {
					subT.Fatalf("failed to setup mock file: %v", err)
				}
				subT.Setenv("RECONSR_IPINFO", "env_ipinfo_key")
			},
			serviceName: "IPinfo",
			expectedKey: "env_ipinfo_key",
		},
		{
			name: "env var works when file key is missing",
			setupMock: func(subT *testing.T, _, _ string) {
				subT.Setenv("RECONSR_LEAKIX", "env_leakix_only")
			},
			serviceName: "LeakIX",
			expectedKey: "env_leakix_only",
		},
		{
			name: "env secret file takes precedence over env var",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				secretFilePath := filepath.Join(secretsPath, "custom_hunter.txt")
				if err := os.WriteFile(secretFilePath, []byte("hunter_secret_key\n"), 0o600); err != nil {
					subT.Fatalf("failed to setup secret file: %v", err)
				}
				subT.Setenv("RECONSR_HUNTERIO_FILE", secretFilePath)
				subT.Setenv("RECONSR_HUNTERIO", "env_hunter_fallback")
			},
			serviceName: "Hunterio",
			expectedKey: "hunter_secret_key",
		},
		{
			name: "env secret file missing falls back to env var",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				subT.Setenv("RECONSR_ABUSEIPDB_FILE", filepath.Join(secretsPath, "nonexistent.txt"))
				subT.Setenv("RECONSR_ABUSEIPDB", "env_abuse_fallback")
			},
			serviceName: "AbuseIPDB",
			expectedKey: "env_abuse_fallback",
		},
		{
			name: "env secret file oversized falls back to env var",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				oversizedFilePath := filepath.Join(secretsPath, "oversized.txt")
				oversizedContent := []byte(strings.Repeat("A", 4097))
				if err := os.WriteFile(oversizedFilePath, oversizedContent, 0o600); err != nil {
					subT.Fatalf("failed to write oversized file: %v", err)
				}
				subT.Setenv("RECONSR_CIRCL_FILE", oversizedFilePath)
				subT.Setenv("RECONSR_CIRCL", "env_circl_fallback")
			},
			serviceName: "Circl",
			expectedKey: "env_circl_fallback",
		},
		{
			name: "direct secret with prefixed name in secrets directory takes precedence",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				secretFilePath := filepath.Join(secretsPath, "reconsr_haveibeenpwned")
				if err := os.WriteFile(secretFilePath, []byte("  pwned_secret_val \n"), 0o600); err != nil {
					subT.Fatalf("failed to write secret file: %v", err)
				}
				subT.Setenv("RECONSR_HAVEIBEENPWNED", "env_pwned_fallback")
			},
			serviceName: "HaveIBeenPwned",
			expectedKey: "pwned_secret_val",
		},
		{
			name: "direct secret with service name in secrets directory takes precedence",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				secretFilePath := filepath.Join(secretsPath, "hackertarget")
				if err := os.WriteFile(secretFilePath, []byte("ht_secret_direct"), 0o600); err != nil {
					subT.Fatalf("failed to write secret file: %v", err)
				}
				subT.Setenv("RECONSR_HACKERTARGET", "env_ht_fallback")
			},
			serviceName: "HackerTarget",
			expectedKey: "ht_secret_direct",
		},
		{
			name: "empty secret file in secrets directory falls back to env var",
			setupMock: func(subT *testing.T, _, secretsPath string) {
				secretFilePath := filepath.Join(secretsPath, "reconsr_shodan")
				if err := os.WriteFile(secretFilePath, []byte("   \n"), 0o600); err != nil {
					subT.Fatalf("failed to write empty secret file: %v", err)
				}
				subT.Setenv("RECONSR_SHODAN", "env_shodan_fallback")
			},
			serviceName: "Shodan",
			expectedKey: "env_shodan_fallback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(subT *testing.T) {
			tempDir := subT.TempDir()
			mockPath := filepath.Join(tempDir, "keys.txt")
			secretsPath := filepath.Join(tempDir, "secrets")
			if err := os.MkdirAll(secretsPath, 0o700); err != nil {
				subT.Fatalf("failed to create secrets dir: %v", err)
			}

			resetForTest(mockPath, secretsPath)

			if tt.setupMock != nil {
				tt.setupMock(subT, mockPath, secretsPath)
			}

			got := GetKey(tt.serviceName)
			if got != tt.expectedKey {
				subT.Errorf("GetKey(%q) = %q, want %q", tt.serviceName, got, tt.expectedKey)
			}
		})
	}
}

func TestReadSecretEmptyPath(t *testing.T) {
	if got := readSecretFile(""); got != "" {
		t.Errorf("readSecretFile(\"\") = %q, want empty string", got)
	}
	if got := readSecretFile("."); got != "" {
		t.Errorf("readSecretFile(\".\") = %q, want empty string", got)
	}
	if got := readSecretFile("/"); got != "" {
		t.Errorf("readSecretFile(\"/\") = %q, want empty string", got)
	}
}
