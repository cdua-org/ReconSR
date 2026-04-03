// Package scopemanager handles the "Out of Scope" logic for the ReconSR application.
// It identifies entities that should be recorded in the graph but not processed further.
package scopemanager

import (
	"bufio"
	"embed"
	"net"
	"os"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
)

//go:embed default_scope.txt
var defaultScope embed.FS

const configDir = "configs"
const configFile = "configs/scope.txt"

var (
	// blockedDotDomains stores domains with a leading dot (e.g., ".example.com")
	blockedDotDomains []string
	// blockedNets stores IP ranges
	blockedNets []*net.IPNet
	// blockedGeneric stores exact matches for other types: map[type]map[value]struct{}
	blockedGeneric map[string]map[string]struct{}
	mu             sync.RWMutex
)

// Setup ensures that the scope configuration file exists.
func Setup() error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		content, err := defaultScope.ReadFile("default_scope.txt")
		if err != nil {
			return err
		}
		if err := os.WriteFile(configFile, content, 0600); err != nil {
			return err
		}
	}
	return Load()
}

// Load reads the scope configuration from the file into memory.
func Load() (err error) {
	mu.Lock()
	defer mu.Unlock()

	blockedDotDomains = nil
	blockedNets = nil
	blockedGeneric = make(map[string]map[string]struct{})

	file, fErr := os.Open(configFile)
	if fErr != nil {
		return fErr
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	var currentSection string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(line[1 : len(line)-1])
			continue
		}

		if currentSection == "" {
			continue
		}

		normalizedLine := strings.ReplaceAll(line, ",", " ")
		for _, el := range strings.Fields(normalizedLine) {
			val := strings.ToLower(el)
			switch currentSection {
			case "domain", "subdomain":
				// Normalize domain/subdomain using validator (handles Punycode/IDN)
				res, err := validator.Validate("domain", val)
				if err == nil {
					val = res.Value
					if !strings.HasPrefix(val, ".") {
						val = "." + val
					}
					blockedDotDomains = append(blockedDotDomains, val)
				}
			case "ip", "ipv4", "ipv6", "ipv4_ambiguous":
				if !strings.Contains(val, "/") {
					if strings.Contains(val, ":") {
						val += "/128"
					} else {
						val += "/32"
					}
				}
				if _, ipnet, err := net.ParseCIDR(val); err == nil {
					blockedNets = append(blockedNets, ipnet)
				}
			default:
				// Exact text match for any other types
				if blockedGeneric[currentSection] == nil {
					blockedGeneric[currentSection] = make(map[string]struct{})
				}
				blockedGeneric[currentSection][val] = struct{}{}
			}
		}
	}
	return scanner.Err()
}

// IsOutOfScope checks if the entity is outside project boundaries.
// Expects normalized values from validator.
func IsOutOfScope(entityType, value string) bool {
	mu.RLock()
	defer mu.RUnlock()

	switch entityType {
	case "domain", "subdomain":
		dotVal := "." + value
		for _, d := range blockedDotDomains {
			if strings.HasSuffix(dotVal, d) {
				return true
			}
		}
	case "ip", "ipv4", "ipv6", "ipv4_ambiguous":
		ip := net.ParseIP(value)
		if ip == nil {
			return false
		}
		for _, bNet := range blockedNets {
			if bNet.Contains(ip) {
				return true
			}
		}
	default:
		// Check generic exact match table
		if typeMap, ok := blockedGeneric[entityType]; ok {
			if _, blocked := typeMap[value]; blocked {
				return true
			}
		}
	}

	return false
}
