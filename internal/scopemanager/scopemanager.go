// Package scopemanager handles the "Out of Scope" logic for the ReconSR application.
// It identifies entities that should be recorded in the graph but not processed further.
package scopemanager

import (
	"bufio"
	"context"
	"embed"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cdua-org/ReconSR/internal/validator"
)

//go:embed default_scope.txt
var defaultScope embed.FS

const (
	scopeDir  = "configs/scope"
	mainScope = "configs/scope/scope.txt"
)

var (
	// blockedDotDomains stores domains with a leading dot (e.g., ".example.com")
	blockedDotDomains map[string]struct{}
	// blockedNets stores IP ranges
	blockedNets []*net.IPNet
	// blockedGeneric stores exact matches for other types
	blockedGeneric map[string]map[string]struct{}

	// allowedDotDomains stores exception domains with a leading dot
	allowedDotDomains map[string]struct{}
	// allowedNets stores exception IP ranges
	allowedNets []*net.IPNet
	// allowedGeneric stores exception exact matches for other types
	allowedGeneric map[string]map[string]struct{}

	mu sync.RWMutex
)

// Setup ensures that the scope configuration directory and default file exist.
func Setup(ctx context.Context) error {
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.MkdirAll(scopeDir, 0700); err != nil {
		return err
	}
	if _, err := root.Stat(mainScope); os.IsNotExist(err) {
		content, err := defaultScope.ReadFile("default_scope.txt")
		if err != nil {
			return err
		}
		if err := root.WriteFile(mainScope, content, 0600); err != nil {
			return err
		}
	}
	return Load(ctx)
}

// Load reads all scope configuration files from the scope directory into memory.
func Load(ctx context.Context) error {
	newBlockedDotDomains := make(map[string]struct{})
	newBlockedNets := make([]*net.IPNet, 0)
	newBlockedGeneric := make(map[string]map[string]struct{})

	newAllowedDotDomains := make(map[string]struct{})
	newAllowedNets := make([]*net.IPNet, 0)
	newAllowedGeneric := make(map[string]map[string]struct{})

	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()

	entries, err := os.ReadDir(scopeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		path := filepath.Join(scopeDir, entry.Name())
		allowed, blocked, err := parseRawFile(ctx, root, path, "")
		if err != nil {
			return err
		}

		processRaw(allowed, newAllowedDotDomains, &newAllowedNets, newAllowedGeneric)
		processRaw(blocked, newBlockedDotDomains, &newBlockedNets, newBlockedGeneric)
	}

	mu.Lock()
	defer mu.Unlock()

	blockedDotDomains = newBlockedDotDomains
	blockedNets = newBlockedNets
	blockedGeneric = newBlockedGeneric

	allowedDotDomains = newAllowedDotDomains
	allowedNets = newAllowedNets
	allowedGeneric = newAllowedGeneric

	return nil
}

// parseRawFile reads the file and sorts items into raw string maps by section.
func parseRawFile(ctx context.Context, root *os.Root, name, defaultSection string) (allowed, blocked map[string][]string, err error) {
	allowed = make(map[string][]string)
	blocked = make(map[string][]string)

	file, fErr := root.Open(name)
	if fErr != nil {
		return nil, nil, fErr
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	currentSection := defaultSection
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}

		if currentSection == "" {
			continue
		}

		normalizedLine := strings.ReplaceAll(line, ",", " ")
		for _, el := range strings.Fields(normalizedLine) {
			val := el

			isAllowed := false
			if strings.HasPrefix(val, "!") {
				isAllowed = true
				val = strings.TrimPrefix(val, "!")
			}

			if isAllowed {
				allowed[currentSection] = append(allowed[currentSection], val)
			} else {
				blocked[currentSection] = append(blocked[currentSection], val)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return allowed, blocked, nil
}

func processRaw(
	raw map[string][]string,
	outDotDomains map[string]struct{},
	outNets *[]*net.IPNet,
	outGeneric map[string]map[string]struct{},
) {
	for section, values := range raw {
		for _, val := range values {
			switch section {
			case "domain", "subdomain":
				cleanVal := strings.TrimPrefix(val, ".")
				testVal := "testscope." + cleanVal
				res, err := validator.Validate("domain", testVal)
				if err != nil {
					continue
				}
				finalVal := strings.TrimPrefix(res.Value, "testscope.")
				if !strings.HasPrefix(finalVal, ".") {
					finalVal = "." + finalVal
				}
				outDotDomains[finalVal] = struct{}{}
			case "ip", "ipv4", "ipv6", "ipv4_ambiguous":
				if !strings.Contains(val, "/") {
					if strings.Contains(val, ":") {
						val += "/128"
					} else {
						val += "/32"
					}
				}
				_, ipnet, err := net.ParseCIDR(val)
				if err != nil {
					continue
				}
				*outNets = append(*outNets, ipnet)
			case "asn":
				res, err := validator.Validate("asn", val)
				if err != nil {
					continue
				}
				if outGeneric["asn"] == nil {
					outGeneric["asn"] = make(map[string]struct{})
				}
				outGeneric["asn"][strings.ToLower(res.Value)] = struct{}{}
			default:
				if outGeneric[section] == nil {
					outGeneric[section] = make(map[string]struct{})
				}
				outGeneric[section][val] = struct{}{}
			}
		}
	}
}

// IsOutOfScope checks if the entity is outside project boundaries.
// Expects normalized values from validator.
func IsOutOfScope(entityType, value string) bool {
	value = strings.ToLower(value)
	mu.RLock()
	defer mu.RUnlock()

	switch entityType {
	case "domain", "subdomain":
		dotVal := "." + value
		current := dotVal
		for {
			if _, ok := allowedDotDomains[current]; ok {
				return false
			}
			if _, ok := blockedDotDomains[current]; ok {
				return true
			}

			idx := strings.IndexByte(current[1:], '.')
			if idx == -1 {
				break
			}
			current = current[idx+1:]
		}
	case "ip", "ipv4", "ipv6", "ipv4_ambiguous":
		ip := net.ParseIP(value)
		if ip == nil {
			return false
		}
		for _, aNet := range allowedNets {
			if aNet.Contains(ip) {
				return false
			}
		}
		for _, bNet := range blockedNets {
			if bNet.Contains(ip) {
				return true
			}
		}
	default:
		if typeMap, ok := allowedGeneric[entityType]; ok {
			if _, allowed := typeMap[value]; allowed {
				return false
			}
		}
		if typeMap, ok := blockedGeneric[entityType]; ok {
			if _, blocked := typeMap[value]; blocked {
				return true
			}
		}
	}

	return false
}
