package controller

import (
	"bufio"
	"cdua-org/ReconSR/internal/dispatcher"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	configDir  = "configs"
	configFile = "configs/config.txt"
)

// GetModuleSettings returns the current module settings from the dispatcher.
func GetModuleSettings() map[string]map[string]bool {
	return dispatcher.GetModuleSettings()
}

// UpdateModuleSettings saves new settings to disk and updates the dispatcher.
func UpdateModuleSettings(ctx context.Context, settings map[string]map[string]bool) error {
	if err := saveConfig(settings); err != nil {
		return err
	}
	return dispatcher.LoadConfig(ctx, settings)
}

// SyncConfig initializes or updates the configuration file.
func SyncConfig(ctx context.Context) error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	allCaps := dispatcher.GetAllCapabilities()

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		defaultSettings := make(map[string]map[string]bool)
		for mod, fns := range allCaps {
			defaultSettings[mod] = make(map[string]bool)
			for _, fn := range fns {
				defaultSettings[mod][fn] = true
			}
		}
		if err := saveConfig(defaultSettings); err != nil {
			return err
		}
		return dispatcher.LoadConfig(ctx, defaultSettings)
	}

	settings, timeout, err := loadConfigFromFile()
	if err != nil {
		return err
	}
	if timeout != 0 {
		dispatcher.SetGlobalTimeout(timeout)
	}

	var toAppend strings.Builder
	newFound := false
	for mod, fns := range allCaps {
		if _, exists := settings[mod]; !exists {
			newFound = true
			fmt.Fprintf(&toAppend, "\n[%s]\n", mod)
			settings[mod] = make(map[string]bool)
			for _, fn := range fns {
				fmt.Fprintf(&toAppend, "#%s\n", fn)
				settings[mod][fn] = false
			}
			continue
		}
		for _, fn := range fns {
			if _, exists := settings[mod][fn]; !exists {
				newFound = true
				fmt.Fprintf(&toAppend, "#%s\n", fn)
				settings[mod][fn] = false
			}
		}
	}

	if newFound {
		f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(toAppend.String()); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	return dispatcher.LoadConfig(ctx, settings)
}

func loadConfigFromFile() (map[string]map[string]bool, time.Duration, error) {
	f, err := os.Open(configFile)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	settings := make(map[string]map[string]bool)
	var timeout time.Duration
	scanner := bufio.NewScanner(f)
	currentMod := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		isCommented := strings.HasPrefix(line, "#")
		raw := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if raw == "" {
			continue
		}

		if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
			currentMod = raw[1 : len(raw)-1]
			if settings[currentMod] == nil {
				settings[currentMod] = make(map[string]bool)
			}
			continue
		}

		if strings.HasPrefix(raw, "timeout") {
			parts := strings.Split(raw, "=")
			if len(parts) == 2 {
				if d, err := time.ParseDuration(strings.TrimSpace(parts[1])); err == nil {
					timeout = d
				}
			}
			continue
		}

		if currentMod != "" {
			if settings[currentMod] == nil {
				settings[currentMod] = make(map[string]bool)
			}
			settings[currentMod][raw] = !isCommented
		}
	}
	return settings, timeout, scanner.Err()
}

func saveConfig(settings map[string]map[string]bool) (err error) {
	f, err := os.OpenFile(configFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err := fmt.Fprintln(f, "# ReconSR Configuration File"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "timeout = %s\n", dispatcher.GetGlobalTimeout()); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(f, "\n# Modules and Functions (comment out with # to disable)"); err != nil {
		return err
	}

	for mod, fns := range settings {
		if _, err := fmt.Fprintf(f, "\n[%s]\n", mod); err != nil {
			return err
		}
		for fn, enabled := range fns {
			prefix := ""
			if !enabled {
				prefix = "#"
			}
			if _, err := fmt.Fprintf(f, "%s%s\n", prefix, fn); err != nil {
				return err
			}
		}
	}
	return nil
}
