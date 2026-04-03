// Package i18n provides internationalization and localization support.
package i18n

import (
	"bufio"
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

// Setup ensures the default language file exists in the lang directory and loads it.
func Setup(langPath string) error {
	dir := filepath.Dir(langPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(langPath); os.IsNotExist(err) {
		content, err := defaultLang.ReadFile("en.txt")
		if err != nil {
			return err
		}
		if err := os.WriteFile(langPath, content, 0644); err != nil {
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			T[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return scanner.Err()
}
