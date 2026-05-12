package controller

import (
	"bufio"
	"cdua-org/ReconSR/internal/dispatcher"
	"context"
	"fmt"
	"os"
	"strconv"
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
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()

	if err := saveConfig(root, settings); err != nil {
		return err
	}
	return dispatcher.LoadConfig(ctx, settings)
}

// SyncConfig initializes or updates the configuration file.
func SyncConfig(ctx context.Context) error {
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	allCaps := dispatcher.GetAllCapabilities()

	if _, err := root.Stat(configFile); os.IsNotExist(err) {
		defaultSettings := make(map[string]map[string]bool)
		for mod, fns := range allCaps {
			defaultSettings[mod] = make(map[string]bool)
			for _, fn := range fns {
				defaultSettings[mod][fn] = true
			}
		}
		if err := dispatcher.LoadConfig(ctx, defaultSettings); err != nil {
			return err
		}
		return saveConfig(root, defaultSettings)
	}

	settings, timeout, globalMax, defConc, maxConc, defDelay, funcLimits, funcDelays, maxDepth, strictDepth, hasMaxDepth, hasStrictDepth, err := loadConfigFromFile(root)
	if err != nil {
		return err
	}
	if timeout != 0 {
		dispatcher.SetGlobalTimeout(timeout)
	}
	dispatcher.ApplyConfigOverrides(maxDepth, strictDepth, globalMax, defConc, maxConc, defDelay, funcLimits, funcDelays)

	if !hasMaxDepth || !hasStrictDepth {
		if err := saveConfig(root, settings); err != nil {
			return err
		}
	}

	var appendOnly strings.Builder
	newFuncsExisting := make(map[string][]string)
	hasNewMods := false
	hasNewFuncsExisting := false

	for mod, fns := range allCaps {
		if _, exists := settings[mod]; !exists {
			hasNewMods = true
			fmt.Fprintf(&appendOnly, "\n[%s]\n", mod)
			settings[mod] = make(map[string]bool)
			for _, fn := range fns {
				fmt.Fprintf(&appendOnly, "#%s concurrency=%d delay=%d\n", fn, dispatcher.DefaultFuncConcurrency, dispatcher.DefaultFuncDelayMs)
				settings[mod][fn] = false
			}
			continue
		}
		for _, fn := range fns {
			if _, exists := settings[mod][fn]; !exists {
				hasNewFuncsExisting = true
				newFuncsExisting[mod] = append(newFuncsExisting[mod], fn)
				settings[mod][fn] = false
			}
		}
	}

	if hasNewFuncsExisting {
		b, err := root.ReadFile(configFile)
		if err != nil {
			return err
		}

		lines := strings.Split(string(b), "\n")
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}

		var out []string
		curMod := ""

		for _, line := range lines {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
				if len(newFuncsExisting[curMod]) > 0 {
					var blanks []string
					for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
						blanks = append(blanks, out[len(out)-1])
						out = out[:len(out)-1]
					}
					for _, fn := range newFuncsExisting[curMod] {
						out = append(out, fmt.Sprintf("#%s concurrency=%d delay=%d", fn, dispatcher.DefaultFuncConcurrency, dispatcher.DefaultFuncDelayMs))
					}
					for i := len(blanks) - 1; i >= 0; i-- {
						out = append(out, blanks[i])
					}
					delete(newFuncsExisting, curMod)
				}
				curMod = trim[1 : len(trim)-1]
			}
			out = append(out, line)
		}

		for _, fn := range newFuncsExisting[curMod] {
			out = append(out, fmt.Sprintf("#%s concurrency=%d delay=%d", fn, dispatcher.DefaultFuncConcurrency, dispatcher.DefaultFuncDelayMs))
		}

		if hasNewMods {
			out = append(out, strings.TrimSuffix(appendOnly.String(), "\n"))
		}

		out = append(out, "")
		if err := root.WriteFile(configFile, []byte(strings.Join(out, "\n")), 0600); err != nil {
			return err
		}
	} else if hasNewMods {
		f, err := root.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(appendOnly.String()); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	return dispatcher.LoadConfig(ctx, settings)
}

func loadConfigFromFile(root *os.Root) (map[string]map[string]bool, time.Duration, *int, *int, *int, *int, map[string]map[string]int, map[string]map[string]int, int, bool, bool, bool, error) {
	f, err := root.Open(configFile)
	if err != nil {
		return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
	}
	defer func() { _ = f.Close() }()

	settings := make(map[string]map[string]bool)
	funcLimits := make(map[string]map[string]int)
	funcDelays := make(map[string]map[string]int)
	var timeout time.Duration
	var globalMax, defConc, maxConc, defDelay *int
	var maxDepth int
	var strictDepth bool
	var hasMaxDepth, hasStrictDepth bool
	var parseErr error

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

		if strings.Contains(raw, "=") && currentMod == "" {
			parts := strings.SplitN(raw, "=", 2)
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			switch key {
			case "max_depth":
				v, err := strconv.Atoi(val)
				if err != nil {
					parseErr = err
				} else {
					maxDepth = v
					hasMaxDepth = true
				}
			case "strict_depth":
				v, err := strconv.ParseBool(val)
				if err != nil {
					parseErr = err
				} else {
					strictDepth = v
					hasStrictDepth = true
				}
			case "timeout":
				d, err := time.ParseDuration(val)
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				timeout = d
			case "global_max_concurrency":
				v, err := strconv.Atoi(val)
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				globalMax = &v
			case "default_func_concurrency":
				v, err := strconv.Atoi(val)
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				defConc = &v
			case "max_allowed_func_concurrency":
				v, err := strconv.Atoi(val)
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				maxConc = &v
			case "default_func_delay":
				v, err := strconv.Atoi(val)
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				defDelay = &v
			}
			continue
		}

		if currentMod != "" {
			if settings[currentMod] == nil {
				settings[currentMod] = make(map[string]bool)
			}
			fields := strings.Fields(raw)
			fnName := fields[0]
			settings[currentMod][fnName] = !isCommented
			for _, field := range fields[1:] {
				kv := strings.SplitN(field, "=", 2)
				if len(kv) != 2 {
					continue
				}
				v, err := strconv.Atoi(kv[1])
				if err != nil {
					return nil, 0, nil, nil, nil, nil, nil, nil, 0, false, false, false, err
				}
				switch kv[0] {
				case "concurrency":
					if funcLimits[currentMod] == nil {
						funcLimits[currentMod] = make(map[string]int)
					}
					funcLimits[currentMod][fnName] = v
				case "delay":
					if funcDelays[currentMod] == nil {
						funcDelays[currentMod] = make(map[string]int)
					}
					funcDelays[currentMod][fnName] = v
				}
			}
		}
	}
	return settings, timeout, globalMax, defConc, maxConc, defDelay, funcLimits, funcDelays, maxDepth, strictDepth, hasMaxDepth, hasStrictDepth, parseErr
}

func saveConfig(root *os.Root, settings map[string]map[string]bool) (err error) {
	f, err := root.OpenFile(configFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
	}()

	if _, err := fmt.Fprintln(f, "# ReconSR Configuration File\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "max_depth = %d\n", dispatcher.MaxDepth); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "strict_depth = %t\n", dispatcher.StrictDepth); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "timeout = %s\n", dispatcher.GetGlobalTimeout()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "global_max_concurrency = %d\n", dispatcher.GlobalMaxConcurrency); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "default_func_concurrency = %d\n", dispatcher.DefaultFuncConcurrency); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "max_allowed_func_concurrency = %d\n", dispatcher.MaxAllowedFuncConcurrency); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "default_func_delay = %d\n", dispatcher.DefaultFuncDelayMs); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(f, "\n# Modules and Functions (comment out with # to disable)"); err != nil {
		return err
	}

	limits, delays := dispatcher.GetFuncDefaults()
	for mod, fns := range settings {
		if _, err := fmt.Fprintf(f, "\n[%s]\n", mod); err != nil {
			return err
		}
		for fn, enabled := range fns {
			prefix := ""
			if !enabled {
				prefix = "#"
			}
			limit := dispatcher.DefaultFuncConcurrency
			delayMs := dispatcher.DefaultFuncDelayMs
			if ml, ok := limits[mod]; ok {
				if v, ok := ml[fn]; ok {
					limit = v
				}
			}
			if md, ok := delays[mod]; ok {
				if v, ok := md[fn]; ok {
					delayMs = v
				}
			}
			if _, err := fmt.Fprintf(f, "%s%s concurrency=%d delay=%d\n", prefix, fn, limit, delayMs); err != nil {
				return err
			}
		}
	}
	return nil
}
