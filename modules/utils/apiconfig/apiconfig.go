// Package apiconfig centralizes credential parsing to eliminate redundant I/O operations across parallel modules.
package apiconfig

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed default_keys.txt
var defaultKeysConfig []byte

const maxSecretSize = 4096

var (
	keysMap        map[string]string
	initOnce       sync.Once
	configFilePath = "configs/keys.txt"
	secretsDir     = "/run/secrets"
)

func init() {
	initOnce.Do(loadConfig)
}

func loadConfig() {
	if strings.HasSuffix(os.Args[0], ".test") && configFilePath == "configs/keys.txt" {
		keysMap = make(map[string]string)
		parseConfig(defaultKeysConfig)
		return
	}

	keysMap = make(map[string]string)

	dir := filepath.Dir(configFilePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		parseConfig(defaultKeysConfig)
		return
	}

	data, err := os.ReadFile(filepath.Clean(configFilePath))
	if err != nil {
		if os.IsNotExist(err) {
			if writeErr := os.WriteFile(configFilePath, defaultKeysConfig, 0o600); writeErr != nil {
				fmt.Fprintf(os.Stderr, "[apiconfig] failed to write default config: %v\n", writeErr)
			}
		}
		parseConfig(defaultKeysConfig)
		return
	}

	parseConfig(data)
}

func parseConfig(content []byte) {
	var currentSection string

	for line := range strings.SplitSeq(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line
			continue
		}

		if currentSection == "[Keys]" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				keysMap[key] = val
			}
		}
	}
}

func readSecretFile(name string) string {
	cleanName := filepath.Base(name)
	if cleanName == "." || cleanName == "/" || cleanName == "" {
		return ""
	}
	targetPath := filepath.Join(secretsDir, cleanName)
	data, err := os.ReadFile(filepath.Clean(targetPath))
	if err != nil {
		return ""
	}
	if len(data) > maxSecretSize {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// GetKey retrieves credentials for a specific provider by evaluating Docker secrets,
// environment variables, and local configuration files in hierarchical order to prioritize secure credential injection.
func GetKey(serviceName string) string {
	initOnce.Do(loadConfig)

	upperName := strings.ToUpper(serviceName)
	if secretName := os.Getenv("RECONSR_" + upperName + "_FILE"); secretName != "" {
		if val := readSecretFile(secretName); val != "" {
			return val
		}
	}

	lowerName := strings.ToLower(serviceName)
	if val := readSecretFile("reconsr_" + lowerName); val != "" {
		return val
	}
	if val := readSecretFile(lowerName); val != "" {
		return val
	}

	if val := os.Getenv("RECONSR_" + upperName); val != "" {
		return val
	}

	return keysMap[serviceName]
}

func resetForTest(mockPath, mockSecretsDir string) {
	keysMap = nil
	initOnce = sync.Once{}
	configFilePath = mockPath
	if mockSecretsDir != "" {
		secretsDir = mockSecretsDir
	} else {
		secretsDir = "/run/secrets"
	}
}
