package whois

import (
	"bufio"
	"regexp"
	"slices"
	"strings"
)

// postalCodeRe is compiled once at package level to avoid per-call overhead.
var postalCodeRe = regexp.MustCompile(`^\d{4,6}$`)

// --- Section header detection (table-driven) ---

type roleMarker struct {
	pattern  string
	role     string
	isPrefix bool
}

// roleMarkers defines section headers in priority order.
// Contains-based checks (colon-bearing) precede HasPrefix checks (bare words)
// to ensure correct precedence on overlap.
var roleMarkers = []roleMarker{
	// Contains: generic ICANN / RPSL / EDUCAUSE
	{"registrar:", roleRegistrar, false},
	{"registrant:", roleRegistrant, false},
	{"administrative contact:", roleAdministrative, false},
	{"billing contact:", roleBilling, false},
	{"admin:", roleAdministrative, false},
	{"administrative:", roleAdministrative, false},
	{"technical contact:", roleTechnical, false},
	{"tech:", roleTechnical, false},
	{"technical:", roleTechnical, false},
	{"abuse:", roleAbuse, false},
	{"abuse contact:", roleAbuse, false},
	{"name servers:", roleNameServers, false},
	{"domain nameservers:", roleNameServers, false},
	{"domain servers in listed order:", roleNameServers, false},

	// Prefix: Italian/generic bare-word sections
	{"admin contact", roleAdministrative, true},
	{"technical", roleTechnical, true},
	{"registrant", roleRegistrant, true},
	{"registrar", roleRegistrar, true},
	{"nameservers", roleNameServers, true},

	// Prefix: Korean name server sections
	{"primary name server", roleNameServers, true},
	{"secondary name server", roleNameServers, true},

	// Prefix: Austrian RPSL-style sections
	{"tech-c:", roleTechnical, true},
	{"admin-c:", roleAdministrative, true},
}

func updateRoleContext(lineLower, currentRole string) string {
	if strings.HasPrefix(lineLower, "contact:") {
		if strings.Contains(lineLower, "administrative") {
			return roleAdministrative
		}
		if strings.Contains(lineLower, "technical") {
			return roleTechnical
		}
		if strings.Contains(lineLower, "billing") {
			return roleBilling
		}
	}

	for _, m := range roleMarkers {
		if m.isPrefix {
			if strings.HasPrefix(lineLower, m.pattern) {
				rest := strings.TrimSpace(lineLower[len(m.pattern):])
				// Allow bare section headers ("Registrar", "Technical Contacts")
				// but block structured fields ("Registrar URL:", "Registrar IANA ID:")
				if !strings.Contains(rest, ":") || rest == ":" || strings.HasPrefix(rest, ": ") {
					return m.role
				}
			}
		} else if strings.Contains(lineLower, m.pattern) {
			return m.role
		}
	}

	// Lines ending with ":" without a value indicate an unknown section
	// header (e.g., "Relevant dates:", "Registration status:").
	// Reset role to prevent data leakage from prior sections.
	if strings.HasSuffix(lineLower, ":") {
		return ""
	}

	return currentRole
}

// --- Regex patterns (all zones consolidated) ---

var whoisPatterns = map[string]*regexp.Regexp{
	// Generic ICANN
	"registrar":   regexp.MustCompile(`(?i)Registrar(?:\s+Name)?\s*:\s+(.*)`),
	"url":         regexp.MustCompile(`(?i)(?:Registrar\s+)?(?:URL|Web)\s*:\s+(.*)`),
	"url_bare":    regexp.MustCompile(`(?i)^\s*(https?://[^\s<>]+)\s*$`),
	"whoisserver": regexp.MustCompile(`(?i)Registrar\s+WHOIS\s+Server\s*:\s+(.*)`),
	"ianaid":      regexp.MustCompile(`(?i)Registrar\s+IANA\s+ID\s*:\s+(.*)`),
	"dnssec":      regexp.MustCompile(`(?i)DNSSEC\s*:\s*(.*)`),

	"creation":   regexp.MustCompile(`(?i)(Creation|Created(?:\s+On)?|Registered(?:\s+on)?|Activated|Registration\s+Time|Registered\s+Time)(?:\s+Date)?\s*:\s+(.*)`),
	"updated":    regexp.MustCompile(`(?i)(Updated|Last[\s-]+Updated|Last[\s-]+Update|Last\s+Modified|Modified|Changed)(?:\s+(?:Date|On))?(?:\s*:\s*|\s+)(.*)`),
	"expiration": regexp.MustCompile(`(?i)(Registry\s+Expiry|Expiration|Expiry|Expire|Expires|Expiration\s+Time|paid-till|Renewal\s+Date)(?:\s+Date)?\s*:\s+(.*)`),
	"ns":         regexp.MustCompile(`(?i)(Name\s+Server|nserver|nameservers?|DNS)\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	"status":     regexp.MustCompile(`(?i)(Domain\s+)?(Status|State)\s*:\s+(.*)`),

	// Registrant contact (ICANN standard)
	"reg_name":  regexp.MustCompile(`(?i)Registrant\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"reg_org":   regexp.MustCompile(`(?i)Registrant\s+Organization\s*:\s+(.*)`),
	"reg_email": regexp.MustCompile(`(?i)Registrant\s+Email\s*:\s+(.*)`),
	"reg_addr":  regexp.MustCompile(`(?i)Registrant\s+(?:Street|Address|City|State/Province|Postal Code|Country|Zip\s+Code)\s*:\s+(.*)`),
	"reg_phone": regexp.MustCompile(`(?i)Registrant\s+Phone\s*:\s+(.*)`),
	"reg_fax":   regexp.MustCompile(`(?i)Registrant\s+Fax\s*:\s+(.*)`),

	// Admin contact (ICANN standard)
	"admin_name":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"admin_org":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Organization\s*:\s+(.*)`),
	"admin_email": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Email\s*:\s+(.*)`),
	"admin_addr":  regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"admin_phone": regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Phone\s*:\s+(.*)`),
	"admin_fax":   regexp.MustCompile(`(?i)(?:Admin|Administrative)\s+Fax\s*:\s+(.*)`),

	// Tech contact (ICANN standard)
	"tech_name":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"tech_org":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Organization\s*:\s+(.*)`),
	"tech_email": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Email\s*:\s+(.*)`),
	"tech_addr":  regexp.MustCompile(`(?i)(?:Tech|Technical)\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"tech_phone": regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Phone\s*:\s+(.*)`),
	"tech_fax":   regexp.MustCompile(`(?i)(?:Tech|Technical)\s+Fax\s*:\s+(.*)`),

	// Billing contact (ICANN standard)
	"billing_name":  regexp.MustCompile(`(?i)Billing\s+(?:Contact\s+)?Name\s*:\s+(.*)`),
	"billing_org":   regexp.MustCompile(`(?i)Billing\s+Organization\s*:\s+(.*)`),
	"billing_email": regexp.MustCompile(`(?i)Billing\s+Email\s*:\s+(.*)`),
	"billing_addr":  regexp.MustCompile(`(?i)Billing\s+(?:Street|Address|City|State/Province|Postal Code|Country)\s*:\s+(.*)`),
	"billing_phone": regexp.MustCompile(`(?i)Billing\s+Phone\s*:\s+(.*)`),
	"billing_fax":   regexp.MustCompile(`(?i)Billing\s+Fax\s*:\s+(.*)`),

	// Abuse contact
	"abuse_email": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Email\s*:\s+(.*)`),
	"abuse_phone": regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Phone\s*:\s+(.*)`),
	"abuse_fax":   regexp.MustCompile(`(?i)Registrar\s+Abuse\s+Contact\s+Fax\s*:\s+(.*)`),

	// Taiwanese .tw WHOIS
	"tw_created":   regexp.MustCompile(`(?i)Record\s+created\s+on\s+(.*)`),
	"tw_expires":   regexp.MustCompile(`(?i)Record\s+expires\s+on\s+(.*)`),
	"tw_registrar": regexp.MustCompile(`(?i)Registration\s+Service\s+Provider\s*:\s+(.*)`),
	"tw_url":       regexp.MustCompile(`(?i)Registration\s+Service\s+URL\s*:\s+(.*)`),

	// RPSL / generic unstructured
	"rpsl_name":  regexp.MustCompile(`(?i)^\s*(?:person(?:name)?|name)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_org":   regexp.MustCompile(`(?i)^\s*(?:organi[zs]ation|org)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_email": regexp.MustCompile(`(?i)^\s*(?:e-mail|email|abuse-email)\s*:\s+(.*)`),
	"rpsl_addr":  regexp.MustCompile(`(?i)^\s*(?:address|street(?:\s+address)?|city|state|postal[\s-]code|country|abuse-postal)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_phone": regexp.MustCompile(`(?i)^\s*(?:phone|tel|abuse-phone)(?:-loc)?\s*:\s+(.*)`),
	"rpsl_fax":   regexp.MustCompile(`(?i)^\s*(?:fax(?:-no)?)(?:-loc)?\s*:\s+(.*)`),

	// Chinese WHOIS
	"cn_registrant":       regexp.MustCompile(`(?i)Registrant\s*:\s+(.+)`),
	"cn_registrant_email": regexp.MustCompile(`(?i)Registrant\s+Contact\s+Email\s*:\s+(.+)`),

	// Japanese WHOIS (JPRS format 1)
	"jp_domain":      regexp.MustCompile(`(?i)a\.\s*\[Domain\s+Name\]\s+(.+)`),
	"jp_org":         regexp.MustCompile(`(?i)g\.\s*\[Organization\]\s+(.+)`),
	"jp_org_type":    regexp.MustCompile(`(?i)l\.\s*\[Organization\s+Type\]\s+(.+)`),
	"jp_admin":       regexp.MustCompile(`(?i)m\.\s*\[Administrative\s+Contact\]\s+(.+)`),
	"jp_tech":        regexp.MustCompile(`(?i)n\.\s*\[Technical\s+Contact\]\s+(.+)`),
	"jp_registered":  regexp.MustCompile(`(?i)\[Registered\s+Date\]\s+(.+)`),
	"jp_connected":   regexp.MustCompile(`(?i)\[Connected\s+Date\]\s+(.+)`),
	"jp_last_update": regexp.MustCompile(`(?i)\[Last\s+Update\]\s+(.+)`),
	"jp_state":       regexp.MustCompile(`(?i)\[State\]\s+(.+)`),
	"jp_lock":        regexp.MustCompile(`(?i)\[Lock\s+Status\]\s+(.+)`),
	"ns_jp":          regexp.MustCompile(`(?i)p\.\s*\[Name\s+Server\]\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),

	// Japanese WHOIS (JPRS format 2 — bracket style)
	"jp2_ns":            regexp.MustCompile(`(?i)\[Name\s+Server\]\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	"jp2_created":       regexp.MustCompile(`(?i)\[Created\s+on\]\s+(.+)`),
	"jp2_expires":       regexp.MustCompile(`(?i)\[Expires\s+on\]\s+(.+)`),
	"jp2_status":        regexp.MustCompile(`(?i)\[Status\]\s+(.+)`),
	"jp2_registrant":    regexp.MustCompile(`(?i)\[Registrant\]\s+(.+)`),
	"jp2_lock":          regexp.MustCompile(`(?i)\[Lock\s+Status\]\s+(.+)`),
	"jp2_updated":       regexp.MustCompile(`(?i)\[Last\s+Updated\]\s+(.+)`),
	"jp2_contact_name":  regexp.MustCompile(`(?i)\[Name\]\s+(.+)`),
	"jp2_contact_email": regexp.MustCompile(`(?i)\[Email\]\s+(.+)`),
	"jp2_postal_code":   regexp.MustCompile(`(?i)\[Postal\s+code\]\s+(.+)`),
	"jp2_address":       regexp.MustCompile(`(?i)\[Postal\s+Address\]\s+(.+)`),
	"jp2_phone":         regexp.MustCompile(`(?i)\[Phone\]\s+(.+)`),
	"jp2_fax":           regexp.MustCompile(`(?i)\[Fax\]\s+(.+)`),

	// Austrian .at WHOIS
	"at_changed": regexp.MustCompile(`(?i)^\s*changed\s*:\s+(.*)`),
	"at_tech_c":  regexp.MustCompile(`(?i)^\s*tech-c\s*:\s+(.*)`),
	"at_admin_c": regexp.MustCompile(`(?i)^\s*admin-c\s*:\s+(.*)`),
	"at_nserver": regexp.MustCompile(`(?i)^\s*nserver\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),

	// Korean .kr WHOIS
	"kr_hostname": regexp.MustCompile(`(?i)Host\s+Name\s*:\s+([a-zA-Z0-9][a-zA-Z0-9.-]*)`),
	"kr_agency":   regexp.MustCompile(`(?i)Authorized\s+Agency\s*:\s+(.*)`),
	"kr_ac_name":  regexp.MustCompile(`(?i)Administrative\s+Contact\(AC\)\s*:\s+(.*)`),
	"kr_ac_email": regexp.MustCompile(`(?i)AC\s+E-Mail\s*:\s+(.*)`),
	"kr_ac_phone": regexp.MustCompile(`(?i)AC\s+Phone\s+Number\s*:\s+(.*)`),
	"kr_reg_zip":  regexp.MustCompile(`(?i)Registrant\s+Zip\s+Code\s*:\s+(.*)`),

	// Brazilian .br WHOIS
	"br_owner":   regexp.MustCompile(`(?i)^owner\s*:\s+(.*)`),
	"br_ownerid": regexp.MustCompile(`(?i)^ownerid\s*:\s+(.*)`),
}

// parseWHOIS leverages regex matching, context tracking, and RPSL fallback.
func parseWHOIS(raw string) Metadata {
	m := Metadata{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	currentRole := ""
	indentedIndex := 0
	lastKey := ""
	handleRoles := make(map[string]string)

	rawLower := strings.ToLower(raw)
	registryType := detectRegistry(rawLower)

	for scanner.Scan() {
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)

		if skipLine(line) {
			if line == "" {
				currentRole = ""
			}
			continue
		}
		if isFooterMarker(line) {
			break
		}
		lineLower := strings.ToLower(line)

		newRole := updateRoleContext(lineLower, currentRole)
		roleChanged := newRole != currentRole
		if roleChanged {
			currentRole = newRole
			indentedIndex = 0
		}

		parts := strings.SplitN(lineLower, ":", 2)
		if len(parts) == 2 && processHandles(parts, handleRoles, &currentRole, registryType) {
			continue
		}

		matched, key := matchPatterns(&m, currentRole, line, lineLower, registryType)
		if matched {
			lastKey = key
			if isDomainLevelKey(key) {
				currentRole = ""
			}
		}

		if matched || roleChanged {
			continue
		}

		if isContinuation(rawLine, line, lastKey) {
			applyContinuation(&m, lastKey, currentRole, line)
			continue
		}

		// Fallback for bare NS hostnames (Italian 2-space indent, etc.).
		if currentRole == roleNameServers {
			addNameServer(&m, strings.Fields(line)[0])
		} else if isFreeformLine(rawLine, line, currentRole) {
			// Indented freeform lines (EDUCAUSE tabs, .uk/.it spaces) or un-indented blocks (.pl).
			classifyIndentedLine(&m, currentRole, line, indentedIndex)
			indentedIndex++
		}
	}
	return m
}

func detectRegistry(rawLower string) string {
	if strings.Contains(rawLower, "\nnic-hdl-br:") || strings.Contains(rawLower, "\nownerid:") {
		return "br"
	}
	if strings.Contains(rawLower, "\nnsset:") {
		return "cz"
	}
	if strings.Contains(rawLower, "\nregistrar:   nicar") || strings.Contains(rawLower, ".com.ar\n") {
		return "ar"
	}
	return ""
}

func isContinuation(rawLine, line, lastKey string) bool {
	return lastKey != "" && leadingSpaces(rawLine) >= 16 && !strings.HasPrefix(line, "[")
}

func isPlaceholder(val string) bool {
	v := strings.ToLower(val)
	return v == "n/a" || v == "none" || v == "null" || v == "-" || v == "." || v == "not applicable"
}

func skipLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//")
}

func isFooterMarker(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(line, ">>>") ||
		strings.HasPrefix(lower, "notice:") ||
		strings.HasPrefix(lower, "terms of use:") ||
		strings.HasPrefix(lower, "the registry database contains")
}

func isDomainLevelKey(key string) bool {
	switch key {
	case "domain", fieldStatus, "ns", "dnssec", "creation", "updated", fieldExpiration,
		"whoisserver", "ianaid", fieldURL:
		return true
	}
	return false
}

func isFreeformLine(rawLine, line, currentRole string) bool {
	return currentRole != "" && (isIndented(rawLine) || !strings.Contains(line, ":"))
}

func processHandles(parts []string, handleRoles map[string]string, currentRole *string, registryType string) bool {
	k := strings.TrimSpace(parts[0])
	v := strings.TrimSpace(parts[1])
	switch k {
	case "registrant":
		if registryType == "cz" || registryType == "ar" {
			handleRoles[v] = roleRegistrant
			return true // Skip parsing handle as Name/Org
		}
	case "admin-c":
		handleRoles[v] = roleAdministrative
		return registryType == "cz" || registryType == "br"
	case "tech-c":
		handleRoles[v] = roleTechnical
		return registryType == "cz" || registryType == "br"
	case "owner-c":
		handleRoles[v] = roleAdministrative
		return registryType == "br"
	case "nic-hdl-br", "nic-hdl", "contact":
		if r, ok := handleRoles[v]; ok {
			*currentRole = r
			return true
		}
	case "nsset":
		*currentRole = roleNameServers
		return true
	}
	return false
}

// matchPatterns iterates over compiled regexes and applies the first match.
func matchPatterns(m *Metadata, currentRole, line, lineLower, registryType string) (matched bool, matchedKey string) {
	for key, re := range whoisPatterns {
		// Context-aware disambiguation to prevent map iteration race conditions
		if strings.HasPrefix(lineLower, "state:") {
			if key == "status" && currentRole != "" {
				continue
			}
			if key == "rpsl_addr" && currentRole == "" {
				continue
			}
		}

		match := re.FindStringSubmatch(line)
		if len(match) <= 1 {
			continue
		}
		val := strings.TrimSpace(match[len(match)-1])
		if isPlaceholder(val) {
			return true, key
		}

		if field, found := strings.CutPrefix(key, "rpsl_"); found {
			applyRPSLMatch(m, currentRole, lineLower, field, val, registryType)
		} else {
			applyWHOISMatch(m, key, val)
		}
		return true, key
	}
	return false, ""
}

// --- NS deduplication helper (DRY) ---

func addNameServer(m *Metadata, val string) {
	hostname := strings.TrimSuffix(strings.TrimSpace(val), ".")
	if hostname == "" || !strings.Contains(hostname, ".") {
		return
	}
	hostname = strings.ToLower(hostname)
	if !slices.Contains(m.NameServers, hostname) {
		m.NameServers = append(m.NameServers, hostname)
	}
}

// leadingSpaces returns the number of leading space characters in a raw line.
func leadingSpaces(rawLine string) int {
	return len(rawLine) - len(strings.TrimLeft(rawLine, " "))
}

// applyContinuation appends a multi-line continuation value to the same
// metadata field that was populated by the previous regex match (lastKey).
// Uses currentRole for context-aware routing of RPSL address fields.
func applyContinuation(m *Metadata, lastKey, currentRole, val string) {
	switch lastKey {
	case "rpsl_addr":
		if target := contactByRole(m, currentRole); target != nil {
			target.Address = appendUnique(target.Address, val)
		}
	case "reg_addr":
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	case "admin_addr":
		m.Admin.Address = appendUnique(m.Admin.Address, val)
	case "tech_addr":
		m.Tech.Address = appendUnique(m.Tech.Address, val)
	case "billing_addr":
		m.Billing.Address = appendUnique(m.Billing.Address, val)
	case "jp2_address", "jp2_postal_code", "kr_reg_zip":
		m.Registrant.Address = appendUnique(m.Registrant.Address, val)
	case "ns":
		addNameServer(m, strings.Fields(val)[0])
	}
}

func contactByRole(m *Metadata, role string) *Contact {
	switch role {
	case roleRegistrar:
		return &m.Registrar
	case roleRegistrant:
		return &m.Registrant
	case roleAdministrative:
		return &m.Admin
	case roleTechnical:
		return &m.Tech
	case roleBilling:
		return &m.Billing
	case roleAbuse:
		return &m.Abuse
	}
	return nil
}

// --- RPSL match ---

func applyRPSLMatch(m *Metadata, currentRole, lineLower, field, val, registryType string) {
	if strings.HasPrefix(lineLower, "abuse-") {
		applyContactMatch(&m.Abuse, "abuse_"+field, "abuse_", val)
		return
	}

	var target *Contact
	switch currentRole {
	case roleRegistrar:
		target = &m.Registrar
	case roleAdministrative:
		target = &m.Admin
	case roleTechnical:
		target = &m.Tech
	case roleBilling:
		target = &m.Billing
	case roleAbuse:
		target = &m.Abuse
	default:
		// Fallbacks go to registrant (e.g. Austrian AT root-level contacts, basic JPRS)
		target = &m.Registrant
	}

	if target != nil {
		switch field {
		case "name":
			if registryType == "ar" {
				target.Organization = appendUnique(target.Organization, val)
			} else {
				target.Name = appendUnique(target.Name, val)
			}
		case fieldOrg:
			target.Organization = appendUnique(target.Organization, val)
		case fieldEmail:
			target.Email = appendUnique(target.Email, val)
		case "addr":
			target.Address = appendUnique(target.Address, val)
		case "phone":
			target.Phone = appendUnique(target.Phone, val)
		case "fax":
			target.Fax = appendUnique(target.Fax, val)
		}
	}
}

// --- Freeform indented-line classification ---

func classifyIndentedLine(m *Metadata, role, line string, lineIndex int) {
	if role == roleNameServers {
		addNameServer(m, strings.Fields(line)[0])
		return
	}

	var target *Contact
	switch role {
	case roleRegistrar:
		target = &m.Registrar
	case roleRegistrant:
		target = &m.Registrant
	case roleAdministrative:
		target = &m.Admin
	case roleTechnical:
		target = &m.Tech
	case roleAbuse:
		target = &m.Abuse
	case roleBilling:
		target = &m.Billing
	default:
		return
	}

	switch {
	case strings.Contains(line, "@"):
		target.Email = appendUnique(target.Email, line)
	case strings.HasPrefix(line, "+"):
		target.Phone = appendUnique(target.Phone, line)
	case lineIndex == 0 && !isLikelyAddress(line):
		target.Name = appendUnique(target.Name, line)
	case lineIndex == 1 && !strings.ContainsAny(line, "0123456789"):
		target.Organization = appendUnique(target.Organization, line)
	default:
		target.Address = appendUnique(target.Address, line)
	}
}

func isIndented(rawLine string) bool {
	return strings.HasPrefix(rawLine, "\t") || strings.HasPrefix(rawLine, "  ")
}

// isLikelyAddress detects standalone geographic tokens (country codes,
// postal codes, city names) that must not be classified as person names.
func isLikelyAddress(line string) bool {
	upper := strings.ToUpper(line)
	if slices.Contains(addressTokens, upper) {
		return true
	}
	return postalCodeRe.MatchString(line)
}

// addressTokens consolidates country codes, region abbreviations, and
// major city names used across Italian, Austrian, and generic WHOIS formats.
var addressTokens = []string{
	// Country codes
	"IT", "US", "UK", "DE", "FR", "ES", "AT", "CH", "NL", "BE",
	// Italian regions
	"MI", "RM", "TO", "NA", "BA", "PA", "VE", "FI", "BO", "MO",
	"CT", "TA", "VA", "BS", "PD", "VR", "GE", "FC", "PI",
	// Major cities
	"MILANO", "ROMA", "NAPOLI", "TORINO", "PALERMO", "GENOVA",
	"BOLOGNA", "FIRENZE", "BARI", "CATANIA", "VERONA", "PADOVA",
	"VENEZIA", "TRIESTE", "BRESCIA", "CAGLIARI", "MESSINA",
	"TARANTO", "ROMAGNA",
}

// --- WHOIS match router ---

func applyWHOISMatch(m *Metadata, key, val string) {
	if applyRegistrarMatch(m, key, val) {
		return
	}
	if applyContactMatch(&m.Registrant, key, "reg_", val) {
		return
	}
	if applyContactMatch(&m.Admin, key, "admin_", val) {
		return
	}
	if applyContactMatch(&m.Tech, key, "tech_", val) {
		return
	}
	if applyContactMatch(&m.Billing, key, "billing_", val) {
		return
	}
	if applyContactMatch(&m.Abuse, key, "abuse_", val) {
		return
	}
	if strings.HasPrefix(key, "tw_") {
		applyTWMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "jp") || strings.HasPrefix(key, "ns_jp") {
		applyJPMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "at_") {
		applyAustrianMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "br_") {
		applyBRMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "kr_") {
		applyKRMatch(m, key, val)
		return
	}
	if strings.HasPrefix(key, "cn_") {
		applyCNMatch(m, key, val)
		return
	}
	applyDomainMatch(m, key, val)
}

func applyTWMatch(m *Metadata, key, val string) {
	switch key {
	case "tw_created":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case "tw_expires":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case "tw_registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
	case "tw_url":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
	}
}

func applyBRMatch(m *Metadata, key, val string) {
	switch key {
	case "br_owner":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "br_ownerid":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	}
}

func applyCNMatch(m *Metadata, key, val string) {
	switch key {
	case "cn_registrant":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "cn_registrant_email":
		m.Registrant.Email = appendUnique(m.Registrant.Email, val)
	}
}
func cleanWhoisServer(val string) string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "http://")
	val = strings.TrimPrefix(val, "https://")
	return strings.TrimSuffix(val, "/")
}

func applyRegistrarMatch(m *Metadata, key, val string) bool {
	switch key {
	case "registrar":
		m.Registrar.Name = appendUnique(m.Registrar.Name, val)
		return true
	case "url", "url_bare":
		if m.RegistrarURL == "" {
			m.RegistrarURL = val
		}
		return true
	case "whoisserver":
		if m.WhoisServer == "" {
			m.WhoisServer = cleanWhoisServer(val)
		}
		return true
	case "ianaid":
		if m.IANAID == "" {
			m.IANAID = val
		}
		return true
	case "dnssec":
		m.DNSSEC = val
		return true
	}
	return false
}

func applyContactMatch(c *Contact, key, prefix, val string) bool {
	if !strings.HasPrefix(key, prefix) {
		return false
	}
	field := strings.TrimPrefix(key, prefix)
	switch field {
	case fieldOrg:
		c.Organization = appendUnique(c.Organization, val)
		return true
	case "name":
		c.Name = appendUnique(c.Name, val)
		return true
	case fieldEmail:
		c.Email = appendUnique(c.Email, val)
		return true
	case "addr":
		c.Address = appendUnique(c.Address, val)
		return true
	case "phone":
		c.Phone = appendUnique(c.Phone, val)
		return true
	case "fax":
		c.Fax = appendUnique(c.Fax, val)
		return true
	}
	return false
}

func applyDomainMatch(m *Metadata, key, val string) {
	switch key {
	case "creation":
		if m.CreationDate == "" {
			m.CreationDate = val
		}
	case "updated":
		if m.UpdatedDate == "" {
			m.UpdatedDate = val
		}
	case "expiration":
		if m.ExpirationDate == "" {
			m.ExpirationDate = val
		}
	case "ns":
		addNameServer(m, val)
	case "status":
		if !slices.Contains(m.DomainStatus, val) {
			m.DomainStatus = append(m.DomainStatus, val)
		}
	case "cn_registrant":
		m.Registrant.Organization = appendUnique(m.Registrant.Organization, val)
	case "cn_registrant_email":
		m.Registrant.Email = appendUnique(m.Registrant.Email, val)
	}
}
