package validator

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrUnsupportedType = errors.New("unsupported_type")
	ErrInvalidSyntax   = errors.New("invalid_syntax")
	ErrInvalidTag      = errors.New("invalid_tag")
)

// Result encapsulates the outcome of a validation operation.
type Result struct {
	Type      string
	Value     string
	Anchor    string
}

// ValidateTag ensures a tag contains only [a-z0-9_-] characters.
func ValidateTag(tag string) error {
	if tag == "" {
		return ErrInvalidTag
	}
	for _, r := range tag {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return ErrInvalidTag
		}
	}
	return nil
}

// Validate checks the syntax of a value against its type and performs normalization.
func Validate(targetType, targetValue string) (Result, error) {
	if targetType == "auto" || targetType == "" {
		if res, err := validateIP(targetValue); err == nil {
			return res, nil
		}
		if res, err := validateEmail(targetValue); err == nil {
			return res, nil
		}
		if res, err := validateDomain(targetValue); err == nil {
			return res, nil
		}
		if res, err := validateASN(targetValue); err == nil {
			return res, nil
		}
		return Result{}, ErrInvalidSyntax
	}

	switch targetType {
	case "domain", "subdomain":
		return validateDomain(targetValue)
	case "ip", "ipv4", "ipv6", "ipv4_ambiguous", "ip4", "ip6":
		return validateIP(targetValue)
	case "email", "email-extra":
		return validateEmail(targetValue)
	case "asn":
		return validateASN(targetValue)
	default:
		// Accept unknown explicit types (like 'btc', 'tel') as-is without syntactic validation
		return Result{
			Type:  targetType,
			Value: targetValue,
		}, nil
	}
}

func validateDomain(value string) (Result, error) {
	domain := strings.TrimSpace(value)
	domain = strings.ToLower(domain)

	if len(domain) > 0 && domain[0] == '.' {
		return Result{}, ErrInvalidSyntax
	}

	domain = strings.TrimSuffix(domain, ".")

	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return Result{}, ErrInvalidSyntax
	}

	l := len(asciiDomain)
	if l < 3 || l > 253 {
		return Result{}, ErrInvalidSyntax
	}

	if asciiDomain[0] == '-' || asciiDomain[l-1] == '-' {
		return Result{}, ErrInvalidSyntax
	}

	if strings.Contains(asciiDomain, "..") || strings.Contains(asciiDomain, ".-") || strings.Contains(asciiDomain, "-.") {
		return Result{}, ErrInvalidSyntax
	}

	parts := strings.Split(asciiDomain, ".")
	if len(parts) < 2 {
		return Result{}, ErrInvalidSyntax
	}

	for _, part := range parts {
		pl := len(part)
		if pl < 1 || pl > 63 {
			return Result{}, ErrInvalidSyntax
		}
		for i := 0; i < pl; i++ {
			c := part[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return Result{}, ErrInvalidSyntax
			}
		}
	}

	lastPart := parts[len(parts)-1]
	onlyDigits := true
	for i := 0; i < len(lastPart); i++ {
		if lastPart[i] < '0' || lastPart[i] > '9' {
			onlyDigits = false
			break
		}
	}
	if onlyDigits {
		return Result{}, ErrInvalidSyntax
	}

	if _, icann := publicsuffix.PublicSuffix(lastPart); !icann {
		return Result{}, ErrInvalidSyntax
	}

	orgDomain, err := getICANNAnchor(asciiDomain)
	if err != nil {
		return Result{}, ErrInvalidSyntax
	}

	correctedType := "subdomain"
	if asciiDomain == orgDomain {
		correctedType = "domain"
	}

	return Result{
		Type:      correctedType,
		Value:     asciiDomain,
		Anchor:    orgDomain,
	}, nil
}

func validateIP(value string) (Result, error) {
	val := strings.TrimSpace(value)

	ip := net.ParseIP(val)
	if ip != nil {
		actualType := "ipv6"
		if ip.To4() != nil {
			actualType = "ipv4"
		}
		return Result{Type: actualType, Value: ip.String()}, nil
	}

	// Check for ambiguous IPv4 (dotted quad with potential leading zeros)
	if strings.Contains(val, ".") && !strings.Contains(val, ":") {
		parts := strings.Split(val, ".")
		if len(parts) == 4 {
			isNumeric := true
			hasLeadingZeros := false
			for _, p := range parts {
				if p == "" {
					isNumeric = false
					break
				}
				for _, r := range p {
					if r < '0' || r > '9' {
						isNumeric = false
						break
					}
				}
				if !isNumeric {
					break
				}
				if len(p) > 1 && p[0] == '0' {
					hasLeadingZeros = true
				}
			}
			if isNumeric && hasLeadingZeros {
				return Result{Type: "ipv4_ambiguous", Value: val}, nil
			}
		}
	}

	return Result{}, ErrInvalidSyntax
}

func validateEmail(value string) (Result, error) {
	val := strings.TrimSpace(value)
	if len(val) > 254 {
		return Result{}, ErrInvalidSyntax
	}

	atIdx := strings.LastIndex(val, "@")
	if atIdx <= 0 || atIdx == len(val)-1 {
		return Result{}, ErrInvalidSyntax
	}

	localPart := val[:atIdx]
	domainPart := val[atIdx+1:]

	if len(localPart) > 64 {
		return Result{}, ErrInvalidSyntax
	}

	resType := "email"

	var domainValue string
	var orgDomain string
	if strings.HasPrefix(domainPart, "[") && strings.HasSuffix(domainPart, "]") {
		resType = "email-extra"
		ipStr := domainPart[1 : len(domainPart)-1]
		if strings.HasPrefix(strings.ToLower(ipStr), "ipv6:") {
			ipStr = ipStr[5:]
		}
		if net.ParseIP(ipStr) == nil {
			return Result{}, ErrInvalidSyntax
		}
		domainValue = domainPart
	} else {
		domainRes, err := validateDomain(domainPart)
		if err != nil {
			return Result{}, ErrInvalidSyntax
		}
		domainValue = domainRes.Value
		orgDomain = domainRes.Anchor
	}

	standardChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+'"
	extraAtextChars := "!#$%&*/=?^{|}~"

	var words []string
	var currentWord strings.Builder
	inQuotes := false
	escaped := false

	for _, r := range localPart {
		if escaped {
			currentWord.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			if !inQuotes {
				return Result{}, ErrInvalidSyntax // escape outside quotes is invalid
			}
			currentWord.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			inQuotes = !inQuotes
			currentWord.WriteRune(r)
			continue
		}
		if r == '.' && !inQuotes {
			words = append(words, currentWord.String())
			currentWord.Reset()
			continue
		}
		currentWord.WriteRune(r)
	}

	if inQuotes || escaped {
		return Result{}, ErrInvalidSyntax // unclosed quotes or trailing escape
	}
	words = append(words, currentWord.String())

	for _, word := range words {
		if len(word) == 0 {
			return Result{}, ErrInvalidSyntax // catches leading/trailing/consecutive dots
		}

		if word[0] == '"' {
			// Quoted string (e.g., "john.doe" or inside obs-local-part like john."q".doe)
			if len(word) < 2 || word[len(word)-1] != '"' {
				return Result{}, ErrInvalidSyntax // partial quotes like a"b
			}
			resType = "email-extra"
			inner := word[1 : len(word)-1]
			innerEscaped := false
			for _, r := range inner {
				if innerEscaped {
					innerEscaped = false
					continue
				}
				if r == '\\' {
					innerEscaped = true
					continue
				}
				if r == '"' {
					return Result{}, ErrInvalidSyntax // unescaped quote inside
				}
			}
		} else {
			// Atom (unquoted string)
			for _, r := range word {
				if r == '"' {
					return Result{}, ErrInvalidSyntax // quotes inside unquoted word
				}
				if strings.ContainsRune(standardChars, r) {
					continue
				}
				if strings.ContainsRune(extraAtextChars, r) {
					resType = "email-extra"
					continue
				}
				return Result{}, ErrInvalidSyntax // invalid characters: ()<>[]:;\, spaces, etc.
			}
		}
	}

	return Result{
		Type:      resType,
		Value:     localPart + "@" + domainValue,
		Anchor:    orgDomain,
	}, nil
}

func validateASN(value string) (Result, error) {
	val := strings.TrimSpace(value)
	if val == "" {
		return Result{}, ErrInvalidSyntax
	}

	val = strings.ToUpper(val)
	if !strings.HasPrefix(val, "AS") {
		val = "AS" + val
	}

	if len(val) <= 2 {
		return Result{}, ErrInvalidSyntax
	}

	for _, c := range val[2:] {
		if c < '0' || c > '9' {
			return Result{}, ErrInvalidSyntax
		}
	}

	return Result{
		Type:  "asn",
		Value: val,
	}, nil
}

func getICANNAnchor(domain string) (string, error) {
	_, isICANN := publicsuffix.PublicSuffix(domain)
	if isICANN {
		return publicsuffix.EffectiveTLDPlusOne(domain)
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		sub := strings.Join(parts[i:], ".")
		_, ic := publicsuffix.PublicSuffix(sub)
		if ic {
			anchor, err := publicsuffix.EffectiveTLDPlusOne(sub)
			if err == nil {
				return anchor, nil
			}
			return strings.Join(parts[i-1:], "."), nil
		}
	}

	anchor, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		suffix, icannSuffix := publicsuffix.PublicSuffix(domain)
		if suffix == domain && !icannSuffix {
			return domain, nil
		}
		return "", err
	}
	return anchor, nil
}
