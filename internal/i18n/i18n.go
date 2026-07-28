// Package i18n provides internationalization and localization support.
package i18n

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

//go:embed en.txt
var defaultLang embed.FS

// T is the global translation map.
var T = make(map[string]string)

// Get returns the localized string for key, or an update warning if empty/missing.
func Get(key string) string {
	if val, ok := T[key]; ok && strings.TrimSpace(val) != "" {
		return val
	}
	return "[UPDATE LANG FILE: " + key + "]"
}

// Setup ensures the default language file exists in the lang directory and loads it.
func Setup(langPath string) error {
	dir := filepath.Dir(langPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	if _, err := os.Stat(langPath); os.IsNotExist(err) {
		content, err := defaultLang.ReadFile("en.txt")
		if err != nil {
			return err
		}
		if err := os.WriteFile(langPath, content, 0600); err != nil {
			return err
		}
	}
	return LoadLanguage(langPath)
}

// LoadLanguage reads the specified language file and populates the translation map.
func LoadLanguage(path string) (err error) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) || strings.HasPrefix(cleanPath, "..") {
		return errors.New("invalid path")
	}

	defaultKeys := make(map[string]struct{})
	defaultContent, err := defaultLang.ReadFile("en.txt")
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewReader(defaultContent))
	for scanner.Scan() {
		line := scanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			if k != "" && !strings.HasPrefix(k, "#") {
				defaultKeys[k] = struct{}{}
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return scanErr
	}

	file, fErr := os.Open(cleanPath)
	if fErr != nil {
		return fErr
	}
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}()

	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				T[k] = v
			}
		}
	}

	for k := range defaultKeys {
		if val, exists := T[k]; !exists || strings.TrimSpace(val) == "" {
			T[k] = "[UPDATE LANG FILE: " + k + "]"
		}
	}

	return fileScanner.Err()
}
