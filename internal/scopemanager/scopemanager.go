// Package scopemanager handles the "Out of Scope" logic for the ReconSR application.
// It identifies entities that should be recorded in the graph but not processed further.
package scopemanager

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
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

	lastDirFingerprint string
	lastSemanticHash   string

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
	_, err = Load(ctx)
	return err
}

// Load reads all scope configuration files from the scope directory into memory.
// It returns true if rules were modified since the last load.
func Load(ctx context.Context) (changed bool, err error) {
	entries, err := os.ReadDir(scopeDir)
	if err != nil {
		if os.IsNotExist(err) {
			mu.Lock()
			defer mu.Unlock()
			if lastSemanticHash == "" {
				return false, nil
			}
			blockedDotDomains = make(map[string]struct{})
			blockedNets = make([]*net.IPNet, 0)
			blockedGeneric = make(map[string]map[string]struct{})
			allowedDotDomains = make(map[string]struct{})
			allowedNets = make([]*net.IPNet, 0)
			allowedGeneric = make(map[string]map[string]struct{})
			lastDirFingerprint = ""
			lastSemanticHash = ""
			return true, nil
		}
		return false, err
	}

	var fpBuilder strings.Builder
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		info, iErr := entry.Info()
		if iErr != nil {
			return false, iErr
		}
		fpBuilder.WriteString(fmt.Sprintf("%s:%d:%d;", entry.Name(), info.Size(), info.ModTime().UnixNano()))
	}
	currentFingerprint := fpBuilder.String()

	mu.RLock()
	if lastDirFingerprint != "" && currentFingerprint == lastDirFingerprint {
		mu.RUnlock()
		return false, nil
	}
	mu.RUnlock()

	root, err := os.OpenRoot(".")
	if err != nil {
		return false, err
	}
	defer root.Close()

	newBlockedDotDomains := make(map[string]struct{})
	newBlockedNets := make([]*net.IPNet, 0)
	newBlockedGeneric := make(map[string]map[string]struct{})

	newAllowedDotDomains := make(map[string]struct{})
	newAllowedNets := make([]*net.IPNet, 0)
	newAllowedGeneric := make(map[string]map[string]struct{})

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		path := filepath.Join(scopeDir, entry.Name())
		allowed, blocked, pErr := parseRawFile(ctx, root, path, "")
		if pErr != nil {
			return false, pErr
		}

		processRaw(allowed, newAllowedDotDomains, &newAllowedNets, newAllowedGeneric)
		processRaw(blocked, newBlockedDotDomains, &newBlockedNets, newBlockedGeneric)
	}

	newSemanticHash := computeSemanticHash(
		newBlockedDotDomains, newAllowedDotDomains,
		newBlockedNets, newAllowedNets,
		newBlockedGeneric, newAllowedGeneric,
	)

	mu.Lock()
	defer mu.Unlock()

	lastDirFingerprint = currentFingerprint

	if lastSemanticHash != "" && lastSemanticHash == newSemanticHash {
		return false, nil
	}

	blockedDotDomains = newBlockedDotDomains
	blockedNets = newBlockedNets
	blockedGeneric = newBlockedGeneric

	allowedDotDomains = newAllowedDotDomains
	allowedNets = newAllowedNets
	allowedGeneric = newAllowedGeneric

	lastSemanticHash = newSemanticHash
	return true, nil
}

func computeSemanticHash(
	bDot, aDot map[string]struct{},
	bNets, aNets []*net.IPNet,
	bGen, aGen map[string]map[string]struct{},
) string {
	h := sha256.New()

	writeMap := func(prefix string, m map[string]struct{}) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			h.Write([]byte(prefix + ":" + k + "\n"))
		}
	}

	writeNets := func(prefix string, nets []*net.IPNet) {
		strs := make([]string, 0, len(nets))
		for _, n := range nets {
			if n != nil {
				strs = append(strs, n.String())
			}
		}
		slices.Sort(strs)
		for _, s := range strs {
			h.Write([]byte(prefix + ":" + s + "\n"))
		}
	}

	writeGeneric := func(prefix string, gen map[string]map[string]struct{}) {
		sections := make([]string, 0, len(gen))
		for sec := range gen {
			sections = append(sections, sec)
		}
		slices.Sort(sections)
		for _, sec := range sections {
			keys := make([]string, 0, len(gen[sec]))
			for k := range gen[sec] {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				h.Write([]byte(prefix + ":" + sec + ":" + k + "\n"))
			}
		}
	}

	writeMap("bDot", bDot)
	writeMap("aDot", aDot)
	writeNets("bNets", bNets)
	writeNets("aNets", aNets)
	writeGeneric("bGen", bGen)
	writeGeneric("aGen", aGen)

	return hex.EncodeToString(h.Sum(nil))
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
	isSectionAllowed := false
	if strings.HasPrefix(currentSection, "!") {
		isSectionAllowed = true
		currentSection = strings.TrimPrefix(currentSection, "!")
	}

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
			isSectionAllowed = false
			if strings.HasPrefix(currentSection, "!") {
				isSectionAllowed = true
				currentSection = strings.TrimPrefix(currentSection, "!")
			}
			continue
		}

		if currentSection == "" {
			continue
		}

		normalizedLine := strings.ReplaceAll(line, ",", " ")
		for _, el := range strings.Fields(normalizedLine) {
			val := el
			isAllowed := isSectionAllowed
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

// IsExplicitlyAllowed checks if the entity matches an explicit allow exception rule.
func IsExplicitlyAllowed(entityType, value string) bool {
	value = strings.ToLower(value)
	mu.RLock()
	defer mu.RUnlock()

	switch entityType {
	case "domain", "subdomain":
		dotVal := "." + value
		current := dotVal
		for {
			if _, ok := allowedDotDomains[current]; ok {
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
				return true
			}
		}
	default:
		if typeMap, ok := allowedGeneric[entityType]; ok {
			if _, allowed := typeMap[value]; allowed {
				return true
			}
		}
	}

	return false
}

