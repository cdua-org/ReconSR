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
	"sync"
)

//go:embed en.txt
var defaultLang embed.FS

var (
	mu sync.RWMutex
	// T is the global translation map.
	T = make(map[string]string)
)

// Get returns the localized string for key, or an update warning if empty/missing.
func Get(key string) string {
	mu.RLock()
	val, ok := T[key]
	mu.RUnlock()

	if ok && strings.TrimSpace(val) != "" {
		return val
	}
	return "[UPDATE LANG FILE: " + key + "]"
}

// Setup ensures the default language file exists in the lang directory and loads it.
func Setup(langPath string) error {
	cleanPath := filepath.Clean(langPath)
	if filepath.IsAbs(cleanPath) || strings.HasPrefix(cleanPath, "..") {
		return errors.New("invalid path")
	}

	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		content, err := defaultLang.ReadFile("en.txt")
		if err != nil {
			return err
		}
		if err := os.WriteFile(cleanPath, content, 0600); err != nil {
			return err
		}
	}
	return LoadLanguage(cleanPath)
}

// LoadLanguage reads the specified language file, populates the translation map, and appends missing default keys.
func LoadLanguage(path string) (err error) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) || strings.HasPrefix(cleanPath, "..") {
		return errors.New("invalid path")
	}

	defaultContent, readErr := defaultLang.ReadFile("en.txt")
	if readErr != nil {
		return readErr
	}

	type langEntry struct {
		key  string
		val  string
		line string
	}

	var defaultEntries []langEntry
	scanner := bufio.NewScanner(bytes.NewReader(defaultContent))
	for scanner.Scan() {
		line := scanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" && !strings.HasPrefix(k, "#") {
				defaultEntries = append(defaultEntries, langEntry{
					key:  k,
					val:  v,
					line: line,
				})
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return scanErr
	}

	fileContent, fileErr := os.ReadFile(cleanPath)
	if fileErr != nil {
		return fileErr
	}

	existingKeys := make(map[string]struct{})
	localMap := make(map[string]string, len(defaultEntries))

	fileScanner := bufio.NewScanner(bytes.NewReader(fileContent))
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" && !strings.HasPrefix(k, "#") {
				existingKeys[k] = struct{}{}
				localMap[k] = v
			}
		}
	}
	if scanErr := fileScanner.Err(); scanErr != nil {
		return scanErr
	}

	var missing []langEntry
	for _, entry := range defaultEntries {
		if _, exists := existingKeys[entry.key]; !exists {
			missing = append(missing, entry)
			localMap[entry.key] = entry.val
		}
	}

	mu.Lock()
	for k, v := range localMap {
		T[k] = v
	}
	mu.Unlock()

	if len(missing) > 0 {
		var buf bytes.Buffer
		if len(fileContent) > 0 && fileContent[len(fileContent)-1] != '\n' {
			buf.WriteByte('\n')
		}

		newKeysHeader := "# NEW KEYS"
		if !bytes.Contains(fileContent, []byte(newKeysHeader)) {
			buf.WriteString("\n# ==========================================\n")
			buf.WriteString("# NEW KEYS\n")
			buf.WriteString("# ==========================================\n")
		}

		for _, entry := range missing {
			buf.WriteString(entry.line)
			buf.WriteByte('\n')
		}

		f, openErr := os.OpenFile(cleanPath, os.O_WRONLY|os.O_APPEND, 0600)
		if openErr != nil {
			return openErr
		}
		defer func() {
			closeErr := f.Close()
			if err == nil && closeErr != nil {
				err = closeErr
			}
		}()

		_, err = f.Write(buf.Bytes())
		if err != nil {
			return err
		}
	}

	return nil
}
